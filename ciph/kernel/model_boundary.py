"""
ciph/kernel/model_boundary - the ONE canonical place inference enters Ciph.

    A real invocation and a simulated response must never be confused.

WHAT THIS IS. A thin boundary over the EXISTING clients (`OllamaBrain` for the local server, `CiphRouter`
for the configured provider). It is not a second brain: it constructs no prompts of its own beyond passing
the selected context through, it holds no credentials, and it grants nothing.

WHAT IT RECORDS, for every invocation: the provider, the model identity, whether the run was a REAL_MODEL or
a TEST_DOUBLE, the input-context REFERENCES, the prompt digest, the output and its digest, the latency, the
budget spent, and any refusal. A refusal records NO output - the boundary never invents one.

WHAT IT REFUSES. It never lets a model mint a finding identity, an execution permit, an authorization or a
completed action: `fabricated_identities` returns every citation in the model's text that does not RESOLVE in
the canonical owner that would hold it. The model's words are recorded as the model's words.
"""

import json
import socket
import sqlite3
import time
import urllib.request
from typing import Any, Dict, List, Optional, Sequence

from ciph.kernel.crucible_types import CrucibleError, digest

MODEL_BOUNDARY_V1 = "MODEL_BOUNDARY_V1"

REAL_MODEL = "REAL_MODEL"
TEST_DOUBLE = "TEST_DOUBLE"
NO_PROVIDER = "NO_MODEL_PROVIDER_REACHABLE"
PROVIDER_ERROR = "MODEL_PROVIDER_ERROR"
BUDGET_EXHAUSTED = "MODEL_BUDGET_EXHAUSTED"
EMPTY_MODEL_OUTPUT = "EMPTY_MODEL_OUTPUT"
REASONING_BUDGET_EXHAUSTED = "REASONING_BUDGET_EXHAUSTED"

LOCAL = "LOCAL_OLLAMA"
CONFIGURED = "CONFIGURED_API"

OLLAMA_HOST = "127.0.0.1"
OLLAMA_PORT = 11434
OLLAMA_CHAT = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/chat"
OLLAMA_TAGS = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}/api/tags"

_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS ciph_model_invocations (
        invocation_id TEXT PRIMARY KEY,
        provider TEXT NOT NULL,
        model_identity TEXT,
        kind TEXT NOT NULL,
        purpose TEXT,
        input_context_json TEXT,
        prompt_digest TEXT,
        output_text TEXT,
        output_digest TEXT,
        latency_seconds REAL,
        budget_units INTEGER NOT NULL,
        refusal_reason TEXT,
        uncertainty TEXT,
        created_at REAL NOT NULL,
        policy_version TEXT NOT NULL
    );
    """,
)


def _connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            connection = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
            connection.row_factory = sqlite3.Row
            return connection
        except sqlite3.OperationalError:
            pass
    connection = sqlite3.connect(db_path, timeout=10.0)
    connection.row_factory = sqlite3.Row
    return connection


def init_schema(connection: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        connection.execute(statement)


def _moment(now: Optional[float]) -> float:
    return time.time() if now is None else float(now)


def _rows(db_path: str, query: str, params: Sequence[Any] = ()) -> List[Dict[str, Any]]:
    connection = _connect(db_path, read_only=True)
    try:
        return [dict(row) for row in connection.execute(query, tuple(params))]
    except sqlite3.Error:
        return []
    finally:
        connection.close()


def _write(db_path: str, query: str, params: Sequence[Any]) -> None:
    connection = _connect(db_path)
    try:
        init_schema(connection)
        connection.execute(query, tuple(params))
        connection.commit()
    finally:
        connection.close()


# ------------------------------------------------------------------ provider reality
def provider_status(*, probe: bool = True, timeout: float = 1.5) -> Dict[str, Any]:
    """
    What is ACTUALLY reachable right now. This is the fact the reality gate rests on.
    """
    local: Dict[str, Any] = {"provider": LOCAL, "endpoint": f"{OLLAMA_HOST}:{OLLAMA_PORT}",
                             "reachable": False, "models": []}
    if probe:
        try:
            socket.create_connection((OLLAMA_HOST, OLLAMA_PORT), timeout=timeout).close()
            with urllib.request.urlopen(OLLAMA_TAGS, timeout=timeout) as response:
                payload = json.loads(response.read())
            local["reachable"] = True
            local["models"] = sorted(str(item.get("name")) for item in payload.get("models", []))
        except Exception as exc:
            local["error"] = type(exc).__name__
    configured: Dict[str, Any] = {"provider": CONFIGURED, "reachable": False,
                                  "note": "requires outbound network AND a configured credential"}
    try:
        import os
        configured["credential_present"] = bool(os.environ.get("DEEPSEEK_API_KEY"))
    except Exception:
        configured["credential_present"] = False
    return {"policy_version": MODEL_BOUNDARY_V1, "local": local, "configured": configured,
            "any_real_provider_reachable": bool(local["reachable"] or configured["reachable"])}


def _local_generate(*, model: str, messages: Sequence[Dict[str, str]], temperature: float,
                    max_tokens: int, timeout: float) -> Dict[str, Any]:
    payload = {"model": str(model), "stream": False, "messages": list(messages),
               "options": {"temperature": float(temperature), "num_predict": int(max_tokens)}}
    request = urllib.request.Request(OLLAMA_CHAT, data=json.dumps(payload).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read())
    return {"text": str(data.get("message", {}).get("content", "")).strip(),
            "model_identity": str(data.get("model") or model)}


# ------------------------------------------------------------------ the boundary
def invoke(db_path: str, *, messages: Sequence[Dict[str, str]], purpose: str,
           context_refs: Sequence[str] = (), provider: str = "auto", model_ref: Optional[str] = None,
           temperature: float = 0.0, max_tokens: int = 256, timeout: float = 240.0,
           simulated_response: Optional[str] = None, budget_units: int = 1,
           allow_network: bool = False, uncertainty: Optional[str] = None,
           now: Optional[float] = None) -> Dict[str, Any]:
    """
    Run ONE inference, or REFUSE and record why. There is no third path.

    `simulated_response` makes the run an explicit TEST_DOUBLE. Otherwise the boundary requires a reachable
    provider; with none it records NO_PROVIDER and stores no output.
    """
    moment = _moment(now)
    prompt_digest = digest({"messages": list(messages)})
    invocation_id = "MOD-" + digest({"prompt": prompt_digest, "purpose": purpose,
                                     "at": moment})[:16].upper()
    common = {"invocation_id": invocation_id, "purpose": str(purpose),
              "input_context": sorted(str(ref) for ref in context_refs), "prompt_digest": prompt_digest,
              "budget_units": int(budget_units), "created_at": moment, "policy_version": MODEL_BOUNDARY_V1}

    if simulated_response is not None:
        # EXPLICITLY a test double. It is never recorded as a real-model result.
        text = str(simulated_response)
        _record(db_path, **common, provider="TEST_DOUBLE", model_identity="test-double",
                kind=TEST_DOUBLE, output=text, latency=0.0, refusal=None, uncertainty=uncertainty)
        return {**common, "provider": "TEST_DOUBLE", "model_identity": "test-double", "kind": TEST_DOUBLE,
                "output": text, "latency_seconds": 0.0, "refused": False,
                "distinguishable_from_a_real_invocation": True,
                "is_real_model_output": False}

    status = provider_status()
    if provider in ("auto", LOCAL) and status["local"]["reachable"]:
        chosen = status["local"]
        model_name = model_ref or (chosen["models"][0] if chosen["models"] else "llama3.2:3b")
        started = time.time()
        try:
            result = _local_generate(model=model_name, messages=messages, temperature=temperature,
                                     max_tokens=max_tokens, timeout=timeout)
        except Exception as exc:
            _record(db_path, **common, provider=LOCAL, model_identity=model_name, kind=REAL_MODEL,
                    output=None, latency=time.time() - started, refusal=f"{PROVIDER_ERROR}:{type(exc).__name__}",
                    uncertainty=uncertainty)
            return {**common, "provider": LOCAL, "model_identity": model_name, "kind": REAL_MODEL,
                    "refused": True, "refusal_reason": f"{PROVIDER_ERROR}:{type(exc).__name__}",
                    "output": None, "is_real_model_output": True, "recorded_no_output": True}
        latency = time.time() - started
        if not str(result["text"]).strip():
            # An EMPTY completion is NOT a successful answer. It is refused and NO output is recorded, so a
            # reasoning model that exhausts its budget or returns nothing cannot be counted as having answered.
            _record(db_path, **common, provider=LOCAL, model_identity=result["model_identity"],
                    kind=REAL_MODEL, output=None, latency=latency, refusal=EMPTY_MODEL_OUTPUT,
                    uncertainty=uncertainty)
            return {**common, "provider": LOCAL, "model_identity": result["model_identity"],
                    "kind": REAL_MODEL, "refused": True, "refusal_reason": EMPTY_MODEL_OUTPUT,
                    "output": None, "is_real_model_output": True, "recorded_no_output": True}
        _record(db_path, **common, provider=LOCAL, model_identity=result["model_identity"],
                kind=REAL_MODEL, output=result["text"], latency=latency, refusal=None,
                uncertainty=uncertainty)
        return {**common, "provider": LOCAL, "model_identity": result["model_identity"], "kind": REAL_MODEL,
                "output": result["text"], "latency_seconds": latency, "refused": False,
                "is_real_model_output": True}

    if provider in ("auto", CONFIGURED) and status["configured"].get("credential_present") and allow_network:
        # A configured remote provider is only attempted when the caller EXPLICITLY permits network egress.
        from ciph_router import CiphRouter
        # Forward the FULL prompt through: the system instruction is a real message, and dropping it
        # (passing `purpose` as the system prompt) silently strips any output contract the caller set.
        system_prompt = ""
        dialogue: List[Dict[str, str]] = []
        for message in messages:
            role = str(message.get("role", ""))
            if role == "system" and not system_prompt:
                system_prompt = str(message.get("content", ""))
            else:
                dialogue.append({"role": role, "content": str(message.get("content", ""))})
        started = time.time()
        # HONOR the requested model id: the router must SERVE the model the caller asked for, so the recorded
        # identity matches what the provider actually served. Previously model_ref was recorded but IGNORED
        # (the router always used its environment model), so a run could record one id and serve another.
        router = CiphRouter(model=model_ref) if model_ref else CiphRouter()
        served_model = getattr(router, "model", None) or model_ref or "configured"
        try:
            text = router.think(dialogue[-1]["content"] if dialogue else "", dialogue[:-1], system_prompt,
                                temperature=temperature, max_tokens=max_tokens)
        except Exception as exc:
            _record(db_path, **common, provider=CONFIGURED, model_identity=served_model, kind=REAL_MODEL,
                    output=None, latency=time.time() - started,
                    refusal=f"{PROVIDER_ERROR}:{type(exc).__name__}", uncertainty=uncertainty)
            return {**common, "provider": CONFIGURED, "kind": REAL_MODEL, "refused": True,
                    "refusal_reason": f"{PROVIDER_ERROR}:{type(exc).__name__}", "output": None,
                    "recorded_no_output": True, "is_real_model_output": True}
        latency = time.time() - started
        if not str(text).strip():
            # Empty content is a FAILURE, never an answer. For a REASONING model an empty completion with
            # finish_reason="length" means the reasoning tokens CONSUMED the whole budget before any final
            # content was emitted - a distinct, diagnosable condition, not a genuinely empty answer.
            finish_reason = getattr(router, "last_finish_reason", None)
            reason = REASONING_BUDGET_EXHAUSTED if finish_reason == "length" else EMPTY_MODEL_OUTPUT
            _record(db_path, **common, provider=CONFIGURED, model_identity=served_model,
                    kind=REAL_MODEL, output=None, latency=latency, refusal=reason, uncertainty=uncertainty)
            return {**common, "provider": CONFIGURED, "model_identity": served_model, "kind": REAL_MODEL,
                    "refused": True, "refusal_reason": reason, "output": None, "finish_reason": finish_reason,
                    "usage": getattr(router, "last_usage", None),
                    "is_real_model_output": True, "recorded_no_output": True}
        _record(db_path, **common, provider=CONFIGURED, model_identity=served_model,
                kind=REAL_MODEL, output=text, latency=latency, refusal=None, uncertainty=uncertainty)
        return {**common, "provider": CONFIGURED, "model_identity": served_model,
                "kind": REAL_MODEL, "output": text, "latency_seconds": latency, "refused": False,
                "finish_reason": getattr(router, "last_finish_reason", None),
                "usage": getattr(router, "last_usage", None), "is_real_model_output": True}

    _record(db_path, **common, provider=provider, model_identity=None, kind=REAL_MODEL, output=None,
            latency=0.0, refusal=NO_PROVIDER, uncertainty=uncertainty)
    return {**common, "provider": provider, "kind": None, "refused": True, "refusal_reason": NO_PROVIDER,
            "output": None, "recorded_no_output": True,
            "note": "no provider was reachable; NO output was invented", "provider_status": status}


def _record(db_path: str, *, invocation_id: str, provider: str, model_identity: Optional[str], kind: str,
            purpose: str, input_context: Sequence[str], prompt_digest: str, budget_units: int,
            created_at: float, policy_version: str, output: Optional[str], latency: float,
            refusal: Optional[str], uncertainty: Optional[str]) -> None:
    _write(db_path, "INSERT OR IGNORE INTO ciph_model_invocations (invocation_id, provider, model_identity, "
                    "kind, purpose, input_context_json, prompt_digest, output_text, output_digest, "
                    "latency_seconds, budget_units, refusal_reason, uncertainty, created_at, policy_version) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);",
           (invocation_id, str(provider), model_identity, str(kind), str(purpose),
            json.dumps(sorted(str(ref) for ref in input_context)), prompt_digest, output,
            digest(output) if output is not None else None, float(latency), int(budget_units), refusal,
            uncertainty, float(created_at), MODEL_BOUNDARY_V1))


def invocations(db_path: str, *, kind: Optional[str] = None) -> List[Dict[str, Any]]:
    query = "SELECT * FROM ciph_model_invocations"
    params: Sequence[Any] = ()
    if kind is not None:
        query += " WHERE kind = ?"
        params = (str(kind),)
    query += " ORDER BY created_at, invocation_id;"
    rows = _rows(db_path, query, params)
    for row in rows:
        row["input_context"] = json.loads(row.pop("input_context_json") or "[]")
        row["is_real_model_output"] = row["kind"] == REAL_MODEL and row["output_text"] is not None
    return rows


def reality_gate(db_path: str, *, probe: bool = True) -> Dict[str, Any]:
    """
    The honest state of the model-reality gate, computed from what actually ran.
    """
    real = [row for row in invocations(db_path, kind=REAL_MODEL)
            if row["refusal_reason"] is None and row["output_text"] is not None]
    doubles = invocations(db_path, kind=TEST_DOUBLE)
    status = provider_status(probe=probe)
    if real:
        verdict = "VERIFIED"
    elif status["any_real_provider_reachable"]:
        verdict = "PARTIALLY_VERIFIED"
    else:
        verdict = "UNVERIFIED"
    return {"policy_version": MODEL_BOUNDARY_V1, "verdict": verdict,
            "real_invocations": len(real), "test_double_invocations": len(doubles),
            "provider_status": status,
            "proves": ("that a real local model produced these outputs"
                       if real else "only that the boundary refuses without a provider"),
            "does_not_prove": ("anything about the CREATIVE QUALITY of autonomous research"
                               if real else "that Ciph can reason with a real model at all"),
            "test_double_is_not_real_inference": True}


# ------------------------------------------------------------------ claim validation
def fabricated_identities(db_path: str, text: str) -> List[str]:
    """
    Every citation in the model's text that does NOT resolve in the owner that would hold it.

    A model may describe what it was given. It may not conjure identities that were never issued.
    """
    import re
    candidates = set(re.findall(r"\b(?:F|RS|OBS|EVD|SA|CP)-\d{0,}[A-Z0-9]*\b", str(text)))
    fabricated: List[str] = []
    for candidate in sorted(candidates):
        reference = str(candidate)
        if reference.startswith(("F-", "RS-")):
            known = {row["finding_id"] for row in _rows(db_path, "SELECT finding_id FROM ciph_findings;")}
            known |= {row["result_set_id"] for row in
                      _rows(db_path, "SELECT result_set_id FROM ciph_result_sets;")}
        elif reference.startswith(("OBS-", "EVD-")):
            known = {row["observation_id"] for row in
                     _rows(db_path, "SELECT observation_id FROM ciph_observations;")}
            known |= {row["evidence_id"] for row in _rows(db_path, "SELECT evidence_id FROM ciph_evidence;")}
        elif reference.startswith("SA-"):
            known = {row["standing_auth_id"] for row in
                     _rows(db_path, "SELECT standing_auth_id FROM ciph_standing_authorizations;")}
        elif reference.startswith("CP-"):
            known = {row["proposal_id"] for row in
                     _rows(db_path, "SELECT proposal_id FROM ciph_curiosity_proposals;")}
        else:
            known = set()
        if reference not in known:
            fabricated.append(reference)
    return fabricated


def selected_context(db_path: str, *, expedition_id: str, limit: int = 12,
                     now: Optional[float] = None) -> Dict[str, Any]:
    """
    The VERIFIED selected context the model may see: the expedition, its durable findings and the attention
    references - references, not a dump, and never a claim the model can extend.
    """
    moment = _moment(now)
    from ciph.kernel.independent_expeditions import get_expedition
    expedition = get_expedition(db_path, expedition_id)
    refs: List[str] = [f"EXPEDITION:{expedition_id}"]
    findings: List[Dict[str, Any]] = []
    if expedition.get("result_set_id"):
        from ciph.kernel.referential_continuity import retrieve_result_set
        try:
            retrieved = retrieve_result_set(db_path, expedition["result_set_id"], actor="operator:operator")
            findings = retrieved["findings"][: int(limit)]
            refs.extend(str(item["finding_id"]) for item in findings)
        except CrucibleError:
            findings = []
    if expedition.get("uncertainty_ref"):
        refs.append(str(expedition["uncertainty_ref"]))
    return {"expedition_id": expedition_id, "context_refs": refs, "findings": findings,
            "model_may_see_only_a_reference": True, "checked_at": moment,
            "policy_version": MODEL_BOUNDARY_V1}
