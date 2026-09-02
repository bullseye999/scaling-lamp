"""
ciph.capabilities.commands - Declarative Slash Command Registry (CIPH 4.0).
Eliminates monolithic if/elif dispatch trees and maps commands deterministically to canonical capabilities.
"""

import re
import shlex
import uuid
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Callable, Tuple
from ciph.kernel.policy_engine import AuthorizationTier, ScopeGrant, AuthorizationGrant
from ciph.planner.schemas import IntentProposal


@dataclass
class CommandDefinition:
    command: str                                    # e.g. "/sports"
    capability_name: str                            # e.g. "sports.predict_match"
    description: str                                # e.g. "Probabilistic 5-factor sports prediction"
    aliases: List[str] = field(default_factory=list)# e.g. ["/predict", "/match"]
    param_keys: List[str] = field(default_factory=list) # e.g. ["home", "away"]
    parser_func: Optional[Callable[[str], Dict[str, Any]]] = None
    authorization_tier: AuthorizationTier = AuthorizationTier.AUTO
    help_example: str = ""

    def parse_args(self, arg_str: str) -> Dict[str, Any]:
        """Parse raw argument string into structured parameters dictionary."""
        if self.parser_func:
            return self.parser_func(arg_str.strip())
        
        args = arg_str.strip()
        if not args:
            return {}

        # Default positional splitting
        try:
            tokens = shlex.split(args)
        except Exception:
            tokens = args.split()

        params = {}
        for i, token in enumerate(tokens):
            if i < len(self.param_keys):
                params[self.param_keys[i]] = token
            else:
                params[f"arg_{i+1}"] = token
        return params


class CommandRegistry:
    """
    Declarative Command Registry.
    Replaces massive hardcoded conditional routing with validated manifest dispatch.
    """

    def __init__(self):
        self._commands: Dict[str, CommandDefinition] = {}
        self._aliases: Dict[str, str] = {}
        self._init_default_commands()

    def register(self, cmd_def: CommandDefinition) -> None:
        """Register a command definition and its aliases."""
        cmd_key = cmd_def.command.lower()
        self._commands[cmd_key] = cmd_def
        for alias in cmd_def.aliases:
            self._aliases[alias.lower()] = cmd_key

    def find_command(self, cmd_name: str) -> Optional[CommandDefinition]:
        """Lookup command definition by name or alias."""
        key = cmd_name.lower().strip()
        if key in self._commands:
            return self._commands[key]
        if key in self._aliases:
            primary_key = self._aliases[key]
            return self._commands.get(primary_key)
        return None

    def list_commands(self) -> List[CommandDefinition]:
        """Return list of all primary command definitions."""
        return list(self._commands.values())

    def parse(self, user_input: str) -> Optional[Tuple[CommandDefinition, Dict[str, Any]]]:
        """
        Parse raw user input. If it matches a registered slash command,
        returns (CommandDefinition, parameters_dict), otherwise None.
        """
        line = user_input.strip()
        if not line.startswith("/"):
            return None

        parts = line.split(None, 1)
        cmd_name = parts[0]
        arg_str = parts[1] if len(parts) > 1 else ""

        cmd_def = self.find_command(cmd_name)
        if not cmd_def:
            return None

        params = cmd_def.parse_args(arg_str)
        return cmd_def, params

    def dispatch(
        self,
        user_input: str,
        runtime: Any,
        scope_grant: Optional[ScopeGrant] = None,
        auth_grant: Optional[AuthorizationGrant] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Parse and dispatch command through the runtime's governed reference loop.
        Returns execution result dict, or None if input was not a recognized slash command.
        """
        parsed = self.parse(user_input)
        if not parsed:
            return None

        cmd_def, params = parsed
        
        # Check missing required parameters
        missing = [k for k in cmd_def.param_keys if k not in params or not params[k]]
        proposal_id = f"cmd_{uuid.uuid4().hex[:8]}"

        proposal = IntentProposal(
            proposal_id=proposal_id,
            objective=f"Execute {cmd_def.command}",
            proposed_capability=cmd_def.capability_name,
            provided_parameters=params,
            missing_parameters=missing,
            constraints={"source": "declarative_command", "command": cmd_def.command}
        )

        return runtime.execute_reference_loop(
            proposal=proposal,
            scope_grant=scope_grant,
            auth_grant=auth_grant
        )

    def generate_help_card(self) -> str:
        """Render a clean terminal help card of all registered declarative commands."""
        lines = [
            "╔═══════════════════════════════════════════════════════════════╗",
            "║             CIPH 4.0 DECLARATIVE COMMAND DIRECTORY            ║",
            "╠═══════════════════════════════════════════════════════════════╣"
        ]
        for cmd in sorted(self._commands.values(), key=lambda c: c.command):
            alias_str = f" (aliases: {', '.join(cmd.aliases)})" if cmd.aliases else ""
            lines.append(f"  {cmd.command:<18} • {cmd.description}{alias_str}")
            if cmd.help_example:
                lines.append(f"    Example: {cmd.help_example}")
        lines.append("╚═══════════════════════════════════════════════════════════════╝")
        return "\n".join(lines)

    def _init_default_commands(self):
        """Initialize standard CIPH 4.0 declarative commands."""
        # /sports
        def _parse_sports(args: str) -> Dict[str, Any]:
            if " vs " in args.lower():
                parts = re.split(r'\s+vs\s+', args, flags=re.IGNORECASE)
                return {"home": parts[0].strip(), "away": parts[1].strip()}
            parts = args.split()
            if len(parts) >= 2:
                return {"home": parts[0], "away": parts[1]}
            elif len(parts) == 1:
                return {"home": parts[0], "away": ""}
            return {}

        self.register(CommandDefinition(
            command="/sports",
            capability_name="sports.predict_match",
            description="5-factor probabilistic match prediction",
            aliases=["/predict", "/match"],
            param_keys=["home", "away"],
            parser_func=_parse_sports,
            help_example="/sports Arsenal vs Chelsea"
        ))

        # /memory
        def _parse_memory(args: str) -> Dict[str, Any]:
            tokens = args.split(None, 1)
            if not tokens:
                return {}
            action = tokens[0].lower()
            if action in ("get", "read", "retrieve") and len(tokens) > 1:
                return {"action": "retrieve", "key": tokens[1].strip(), "target": "local_memory"}
            elif action in ("set", "store", "save") and len(tokens) > 1:
                val_parts = tokens[1].split(None, 1)
                k = val_parts[0]
                v = val_parts[1] if len(val_parts) > 1 else ""
                return {"action": "store", "key": k, "value": v, "target": "local_memory"}
            return {"action": "retrieve", "key": args.strip(), "target": "local_memory"}

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

        # /osint
        self.register(CommandDefinition(
            command="/osint",
            capability_name="osint.find_monetizable_threats",
            description="Triage fresh threat feeds for high-priority bug bounty opportunities",
            aliases=["/threats", "/feed"],
            param_keys=[],
            help_example="/osint"
        ))

        # /cvss
        def _parse_cvss(args: str) -> Dict[str, Any]:
            parts = args.split()
            if len(parts) >= 3:
                try:
                    return {"av": parts[0], "ac": parts[1], "pr": parts[2]}
                except Exception:
                    pass
            return {"vector": args.strip()}

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
