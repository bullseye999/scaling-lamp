"""Declarative slash commands; execution is admitted only by the governed runtime."""
import re
import shlex
import uuid
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable, Tuple
from ciph.kernel.policy_engine import AuthorizationTier, ScopeGrant, AuthorizationGrant
from ciph.contracts.enums import ScopeType
from ciph.planner.schemas import IntentProposal
from ciph.contracts.base import canonical_json


def _assign_arguments(tokens, keys):
    params = {}
    positional = []
    for token in tokens:
        if "=" in token:
            key, value = token.split("=", 1)
            if key not in keys or key in params:
                raise ValueError(f"Unknown or duplicate parameter: {key}")
            params[key] = value
        else:
            positional.append(token)
    available = [key for key in keys if key not in params]
    if len(positional) > len(available):
        raise ValueError("Too many positional arguments")
    params.update(zip(available, positional))
    return params


@dataclass
class CommandDefinition:
    command: str
    capability_name: str
    description: str
    aliases: List[str] = field(default_factory=list)
    param_keys: List[str] = field(default_factory=list)
    parser_func: Optional[Callable[[str], Dict[str, Any]]] = None
    authorization_tier: AuthorizationTier = AuthorizationTier.AUTO
    help_example: str = ""

    def parse_args(self, arg_str: str) -> Dict[str, Any]:
        if self.parser_func:
            return self.parser_func(arg_str.strip())
        return _assign_arguments(shlex.split(arg_str), self.param_keys)


class CommandRegistry:
    def __init__(self):
        self._commands = {}
        self._aliases = {}
        self._pending = {}
        self._pending_lock = threading.Lock()
        self._init_default_commands()
        from ciph.capabilities.local_commands import register_local_commands
        register_local_commands(self)

    def register(self, cmd_def: CommandDefinition) -> None:
        names = [cmd_def.command.lower(), *(a.lower() for a in cmd_def.aliases)]
        if len(set(names)) != len(names) or any(
            name in self._commands or name in self._aliases for name in names
        ):
            raise ValueError("Command or alias is already registered")
        self._commands[names[0]] = cmd_def
        for name in names[1:]:
            self._aliases[name] = names[0]

    def find_command(self, cmd_name: str) -> Optional[CommandDefinition]:
        key = cmd_name.lower().strip()
        return self._commands.get(self._aliases.get(key, key))

    def list_commands(self) -> List[CommandDefinition]:
        return list(self._commands.values())

    def parse(self, user_input: str) -> Optional[Tuple[CommandDefinition, Dict[str, Any]]]:
        line = user_input.strip()
        if not line.startswith("/"):
            return None
        parts = line.split(None, 1)
        definition = self.find_command(parts[0])
        if definition is None:
            return None
        return definition, definition.parse_args(parts[1] if len(parts) > 1 else "")

    @staticmethod
    def _blocked(status, message):
        return {"status": status, "dialogue": message, "receipt": None, "claim": None}

    def dispatch(self, user_input, runtime, scope_grant=None, auth_grant=None):
        try:
            parsed = self.parse(user_input)
        except ValueError as exc:
            return self._blocked("INVALID_ARGUMENTS", f"Invalid command arguments: {exc}")
        if parsed is None:
            if user_input.strip().startswith("/"):
                from ciph.capabilities.command_retirement import disposition
                reason, message = disposition(user_input.strip().split()[0].lower())
                return {**self._blocked("COMMAND_UNAVAILABLE", message), "reason_code": reason}
            return None
        definition, params = parsed
        if definition.command == "/help":
            # Presentation only: no capability execution, receipt, or claim.
            return {"status": "SUCCESS", "dialogue": self.generate_help_card(), "receipt": None}
        if definition.command in ("/capabilities", "/self-knowledge"):
            # Presentation only: derived view from capability ledger, no capability execution, receipt, or claim.
            # Intercepted before mandatory parameter checks to allow both summary and single-capability inspection.
            target_cap = None
            parts = user_input.strip().split(maxsplit=1)
            if len(parts) > 1:
                target_cap = parts[1].strip()
            dialogue = runtime.answer_capability_query(target_cap) if runtime else "Runtime unavailable."
            return {"status": "SUCCESS", "dialogue": dialogue, "receipt": None}
        missing = [key for key in definition.param_keys if key not in params or not params[key]]
        capability = definition.capability_name
        if definition.command == "/memory" and params.get("action") == "store":
            capability = "memory.store"
            if not params.get("value"):
                missing.append("value")
        if not missing:
            if scope_grant is not None:
                if (not isinstance(scope_grant, ScopeGrant)
                        or scope_grant.signing_key_id != runtime.kernel_key_id
                        or not scope_grant.verify_signature(runtime.auth_secret_key)
                        or scope_grant.created_at > time.time()
                        or scope_grant.network_policy_override is not None):
                    return self._blocked("INVALID_SCOPE_GRANT", "A signed, current kernel scope grant without a policy override is required.")
            if capability == "cybersecurity.bounty_scan":
                if scope_grant is None:
                    return self._blocked("SCOPE_REQUIRED", "Bounty scanning requires a signed target-domain scope grant.")
                if scope_grant.scope_type != ScopeType.TARGET_DOMAIN:
                    return self._blocked("INVALID_SCOPE_GRANT", "Bounty scanning requires a target-domain scope grant.")

        # Fresh user invocations are distinct; an authorization response resumes only
        # the exact pending request. Parameter equality alone is not a replay key.
        scope_hash = scope_grant.compute_scope_hash() if isinstance(scope_grant, ScopeGrant) else ""
        binding = canonical_json([definition.command, params, scope_hash])
        proposal_id = f"cmd_{uuid.uuid4().hex}"
        if auth_grant is not None:
            if not isinstance(auth_grant, AuthorizationGrant):
                return self._blocked("INVALID_AUTHORIZATION_SIGNATURE", "An authentic AuthorizationGrant is required.")
            with self._pending_lock:
                pending = self._pending.get(auth_grant.plan_hash)
            if pending is None or pending[0] != binding or pending[2] <= time.monotonic():
                return self._blocked("AUTHORIZATION_MISMATCH", "No matching live command challenge. Submit the command again for authorization.")
            proposal_id = pending[1]
        proposal = IntentProposal(
            proposal_id=proposal_id,
            objective=f"Execute {definition.command}",
            proposed_capability=capability,
            provided_parameters=params,
            missing_parameters=missing,
            constraints={"source": "declarative_command", "command": definition.command},
        )
        result = runtime.execute_reference_loop(proposal, scope_grant=scope_grant, auth_grant=auth_grant)
        if result.get("status") == "AUTHORIZATION_REQUIRED":
            with self._pending_lock:
                now = time.monotonic()
                self._pending = {key: value for key, value in self._pending.items() if value[2] > now}
                if len(self._pending) >= 256:
                    self._pending.pop(next(iter(self._pending)))
                self._pending[result["plan_hash"]] = (binding, proposal_id, now + 300)
        return result

    def generate_help_card(self) -> str:
        lines = ["╔═══════════════════════════════════════════════════════════════╗",
                 "║             CIPH 4.0 DECLARATIVE COMMAND DIRECTORY            ║",
                 "╠═══════════════════════════════════════════════════════════════╣"]
        for cmd in sorted(self._commands.values(), key=lambda item: item.command):
            aliases = f" (aliases: {', '.join(cmd.aliases)})" if cmd.aliases else ""
            lines.append(f"  {cmd.command:<18} • {cmd.description}{aliases}")
            if cmd.help_example:
                lines.append(f"    Example: {cmd.help_example}")
        lines.append("  Other legacy commands are unavailable until a governed adapter exists.")
        lines.append("╚═══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)

    def _init_default_commands(self):
        """Initialize standard CIPH 4.0 declarative commands."""
        # /sports
        def _parse_sports(args: str) -> Dict[str, Any]:
            tokens = shlex.split(args)
            separators = [i for i, token in enumerate(tokens) if token.lower() == "vs"]
            if separators:
                if len(separators) != 1 or any("=" in token for token in tokens):
                    raise ValueError("Use home vs away or home=... away=...")
                index = separators[0]
                return {"home": " ".join(tokens[:index]), "away": " ".join(tokens[index+1:])}
            return _assign_arguments(tokens, ["home", "away"])

        self.register(CommandDefinition(
            command="/sports",
            capability_name="sports.predict_match",
            description="5-factor probabilistic match prediction",
            aliases=["/predict", "/match", "/predict-match"],
            param_keys=["home", "away"],
            parser_func=_parse_sports,
            help_example="/sports Arsenal vs Chelsea"
        ))

        # /memory
        def _parse_memory(args: str) -> Dict[str, Any]:
            tokens = shlex.split(args)
            if not tokens:
                return {}
            if tokens[0].lower() in ("set", "store", "save"):
                parts = tokens[1:]
                if parts and parts[0].startswith(("key=", "value=")):
                    params = _assign_arguments(parts, ["key", "value"])
                else:
                    params = {"key": parts[0] if parts else "", "value": " ".join(parts[1:])}
                return {**params, "action": "store", "target": "local_memory"}
            if tokens[0].lower() in ("get", "read", "retrieve"):
                tokens = tokens[1:]
            return {**_assign_arguments(tokens, ["key"]), "action": "retrieve", "target": "local_memory"}

        self.register(CommandDefinition(
            command="/memory",
            capability_name="memory.retrieve",
            description="Query or update secure encrypted memory vault",
            aliases=["/vault", "/mem"],
            param_keys=["key"],
            parser_func=_parse_memory,
            help_example="/memory get operator_alias"
        ))

        # /bounty
        self.register(CommandDefinition(
            command="/bounty",
            capability_name="cybersecurity.bounty_scan",
            description="Execute passive recon & subdomain takeover scan over Tor",
            aliases=["/bounty-scan", "/scan"],
            param_keys=["target"],
            help_example="/bounty target.com"
        ))

        # /bounty-status
        self.register(CommandDefinition(
            command="/bounty-status",
            capability_name="cybersecurity.bounty_summary",
            description="Inspect active bug bounty programs, targets, and scope policies",
            aliases=["/bounty-programs", "/bounties", "/bounty-list"],
            param_keys=[],
            help_example="/bounty-status"
        ))

        # /osint
        self.register(CommandDefinition(
            command="/osint",
            capability_name="osint.find_monetizable_threats",
            description="Triage fresh threat feeds for high-priority bug bounty opportunities",
            aliases=["/threats", "/feed", "/money-ops", "/bounty-ops"],
            param_keys=[],
            help_example="/osint"
        ))

        # /cvss
        def _parse_cvss(args: str) -> Dict[str, Any]:
            tokens = shlex.split(args)
            if not tokens:
                return {}
            if len(tokens) != 1:
                raise ValueError("Supply one complete CVSS vector")
            vector = tokens[0]
            if vector.startswith("vector="):
                vector = vector[len("vector="):]
            return {"vector": vector}

        self.register(CommandDefinition(
            command="/cvss",
            capability_name="pentest.cvss_calculate",
            description="Compute CVSS 3.1 base score and vector metrics",
            aliases=["/calc-cvss"],
            param_keys=["vector"],
            parser_func=_parse_cvss,
            help_example="/cvss AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        ))

        # /tor
        self.register(CommandDefinition(
            command="/tor",
            capability_name="tor.check_status",
            description="Verify active Tor circuit, exit node IP, and proxy health",
            aliases=["/tor-status", "/circuit"],
            param_keys=[],
            help_example="/tor"
        ))

        # /code-audit
        self.register(CommandDefinition(
            command="/code-audit",
            capability_name="code.audit_dependencies",
            description="Safely inspect and audit package dependencies without auto-pip",
            aliases=["/audit-deps", "/check-deps"],
            param_keys=["target_file"],
            help_example="/code-audit ciph_core.py"
        ))

        # /darknet-status
        self.register(CommandDefinition(
            command="/darknet-status",
            capability_name="darknet.get_status",
            description="Inspect darknet monitor telemetry, feeds count, and active alerts",
            aliases=[],
            param_keys=[],
            help_example="/darknet-status"
        ))

        # /darknet-report
        self.register(CommandDefinition(
            command="/darknet-report",
            capability_name="darknet.get_detailed_report",
            description="Retrieve detailed analysis report of latest darknet intelligence",
            aliases=["/detailed-darknet-scan", "/alerts", "/darknet-alerts"],
            param_keys=[],
            help_example="/darknet-report"
        ))

        # /upgrades
        self.register(CommandDefinition(
            command="/upgrades",
            capability_name="code.list_staged",
            description="List staged code upgrade proposals and artifact validation statuses",
            aliases=["/staged", "/code"],
            param_keys=[],
            help_example="/upgrades"
        ))

        # /apply
        def _parse_apply(args: str) -> Dict[str, Any]:
            return _assign_arguments(shlex.split(args), ["proposal_id"])

        self.register(CommandDefinition(
            command="/apply",
            capability_name="code.promote_upgrade",
            description="Promote and apply staged code upgrade with mandatory operator consent",
            aliases=["/approve", "/apply-code", "/apply-upgrade"],
            param_keys=["proposal_id"],
            parser_func=_parse_apply,
            authorization_tier=AuthorizationTier.MANDATORY_INTERRUPT,
            help_example="/apply UP-001"
        ))

        # /learn
        def _parse_learn(args: str) -> Dict[str, Any]:
            arg = args.strip()
            if not arg:
                return {}
            return {"key": f"knowledge_{uuid.uuid4().hex}", "value": arg, "target": "local_memory"}

        self.register(CommandDefinition(
            command="/learn",
            capability_name="memory.store",
            description="Store operator-supplied text in encrypted command memory",
            aliases=[],
            param_keys=["value"],
            parser_func=_parse_learn,
            help_example="/learn Sun Tzu: all warfare is based on deception"
        ))

        # /library
        self.register(CommandDefinition(
            command="/library",
            capability_name="wisdom.consult_library",
            description="Consult strategic and philosophical library catalog",
            aliases=["/books"],
            param_keys=[],
            help_example="/library"
        ))

        # /book-advice
        def _parse_book_advice(args: str) -> Dict[str, Any]:
            return {"situation": args.strip()}

        self.register(CommandDefinition(
            command="/book-advice",
            capability_name="wisdom.consult_library",
            description="Consult strategic and philosophical library for situational guidance",
            aliases=["/ask-book"],
            param_keys=["situation"],
            parser_func=_parse_book_advice,
            help_example="/book-advice dealing with adversaries"
        ))

        # /trading
        self.register(CommandDefinition(
            command="/trading",
            capability_name="trading.portfolio_check",
            description="Check crypto trading portfolio performance and market health",
            aliases=["/portfolio", "/trade-status", "/portfolio-health"],
            param_keys=[],
            help_example="/trading"
        ))

        # /deadman
        self.register(CommandDefinition(
            command="/deadman",
            capability_name="security.deadman_status",
            description="Inspect the dead man's failsafe switch",
            aliases=["/deadmans-switch", "/failsafe"],
            param_keys=[],
            help_example="/deadman"
        ))

        # /help
        self.register(CommandDefinition(
            command="/help",
            capability_name="system.help",
            description="Display declarative slash command directory",
            aliases=["/?"],
            param_keys=[],
            help_example="/help"
        ))

        # /capabilities
        def _parse_capabilities(args: str) -> Dict[str, Any]:
            target = args.strip()
            return {"target": target} if target else {}

        self.register(CommandDefinition(
            command="/capabilities",
            capability_name="system.capabilities",
            description="Display empirical capability self-knowledge and verified health statuses",
            aliases=["/self-knowledge"],
            param_keys=[],
            parser_func=_parse_capabilities,
            help_example="/capabilities or /capabilities <name>"
        ))
