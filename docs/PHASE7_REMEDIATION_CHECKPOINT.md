# Program 2, Phase 7 — External Evidence and Multi-Tier Sandboxing

Updated: 2026-09-08. This checkpoint supersedes the earlier Milestone 7.0 sealing claims. The operator explicitly authorized implementation, bug fixes, and full local verification on 2026-09-08.

## Where work resumed

RESUME_WORK.md still pointed to Phase 6. Phase 7 contained a feasibility harness and some follow-up patches, but no complete external-source collection/admission pipeline or rootless container runner. The follow-up code still exempted canonical-looking implementations from isolation, discovered surviving processes by mutable environment markers, and included adapters that fabricated successful bounty/OSINT/Tor/prediction results. Those shortcuts are removed.

## Implemented boundaries

- Trusted registration records implementation origin. Class names, module names, missing backend objects, and canonical capability names do not grant sandbox exemptions. External network manifests always require isolation. Arbitrary external collection requires a signed token.
- The disposable-process tier uses a new user/PID/network namespace, a trusted namespace-init launcher, Landlock filesystem restrictions, and a libseccomp kernel filter. The child cannot create IPv4, IPv6, or Unix sockets, use process-memory/ptrace access, enter other namespaces, or create an io_uring bypass. Metadata-mutating chmod/chown/timestamp/xattr and ioctl syscalls are denied separately because Landlock is not a metadata-mutation filter. Raw libc socket calls are tested independently of Python audit hooks.
- Landlock handles filesystem creation/removal/link rights, checks rule-installation errors, and exposes only declared inputs, scratch, explicitly selected interpreter/runtime library paths, and minimal device nodes. Recursive /etc, /dev, virtualenv-root and /proc access are not granted. Landlock does not hide all path existence/stat metadata; a fresh-root container is required for that stronger namespace-visibility property. Runtime library files are deliberate read-only dependencies; this is not a claim that the interpreter can run without any filesystem dependencies.
- A stable trusted init starts the workload with close_fds and session isolation. A private lifecycle pipe distinguishes setup refusal from successful exec; application exits 77/78 remain application failures. The workload never inherits that pipe, signing keys, trust registry, or supervisor memory.
- Teardown uses the namespace lifetime, --kill-child, and pidfds for the trusted init rather than a mutable process name/environment marker. The acceptance suite includes a detached descendant that execs with an empty environment. Uncertain cleanup and interrupted consequential work require reconciliation.
- Nonblocking stdin/stdout/stderr processing has input, total output, wall-time, CPU, address-space, process-count and file-size ceilings. Input rejection precedes all launches. Output diagnostics share the same combined byte ceiling, including malformed UTF-8. Limits are per process where POSIX rlimits have per-process semantics; they are not represented as aggregate cgroup accounting.
- The rootless-container tier uses bubblewrap with a fresh root and explicit mounts. It has no daemon socket, image pulling, privileged mode, or weaker fallback. A container scope selects this runner. LOCAL_ONLY work uses the stricter socket-free execution boundary; access to host-local services is not implicitly granted.

## External evidence flow

Trusted operator source configuration -> signed token binding source policy, parameters and scope -> offline sandbox readiness -> trusted Tor broker -> isolated bounded result handling -> supervisor-signed ExecutionReceipt -> atomic queue/EventStore commit -> authenticated Observation -> attributed OBSERVED claim -> MaterializedWorldview.

`ExternalSource` fixes the URL, reliability class, response-size ceiling and deadline before execution. Source settings and serialized scope are covered by the token signature. Changing the source after token issuance fails validation.

`TorEvidenceBroker` connects only to an operator-configured numeric loopback SOCKS endpoint (9050 by default). Target DNS uses Tor's RESOLVE extension, followed by a SOCKS connection pinned to the returned public IP. Private, loopback, link-local, reserved, unspecified and multicast addresses are rejected. HTTPS retains certificate/hostname validation. There are no caller-supplied credentials/headers, cookies, redirect following, local DNS lookups, automatic decompression or clearnet fallback. Unsupported URL schemes, nonstandard ports and onion sources are refused in this implementation.

The protocol follows the [Tor SOCKS extension specification](https://spec.torproject.org/socks-extensions.html). The configured local SOCKS endpoint is trusted operator infrastructure; the application does not claim cryptographic attestation of that daemon's Tor relay path.

The network-free child receives only bounded result data. The supervisor checks its result against the broker's collected data before signing. If collection occurred but result handling cannot be confirmed, the job requires reconciliation rather than becoming a false pre-execution denial.

External raw bytes remain base64-encoded with a SHA-256 digest in the immutable observation value. Display escaping is derived and never rewrites those bytes. Content cannot register capabilities, select a lane, grant authority or trigger another job. A successful HTTP transport does not verify assertions inside the response.

Source policy ceilings:

| Source class | Maximum assurance | Decay ceiling |
| --- | --- | --- |
| DIRECT_SENSOR | 0.40 | 300 seconds |
| THIRD_PARTY_FEED | 0.40 | 604800 seconds |
| PASSIVE_RECON | 0.40 | 86400 seconds |
| UNVERIFIED_INCOMING | 0.30 | 300 seconds |

All are admitted as source-attributed OBSERVED propositions, never external ground truth. AUTHORITATIVE_LOCAL is rejected for external sources. Freshness is bounded by the older observation/collection anchor. Phase 6 curiosity remains offline and does not acquire permission to use external sources.

## Operator integration

Use the existing trusted runtime and an authorized domain scope; registration does not itself dispatch anything:

```python
from ciph.perception.external_sources import ExternalSource
from ciph.contracts.enums import ReliabilityClass
from ciph.planner.schemas import IntentProposal

capability = runtime.register_external_source(ExternalSource(
    source_id="approved_feed",
    url="https://example.com/feed",
    reliability=ReliabilityClass.THIRD_PARTY_FEED,
))
proposal = IntentProposal(
    proposal_id="operator-chosen-unique-id",
    objective="Collect the approved external feed",
    proposed_capability=capability,
    provided_parameters={"target": "example.com"},
)
result = runtime.execute_reference_loop(proposal, scope_grant=authorized_domain_scope)
```

This is configuration/API documentation, not a record of a live fetch performed during verification. Registering Python capabilities remains a trusted operator/developer operation; untrusted source text must be passed to a sandbox as data, never imported into the supervisor.

Legacy network capabilities whose backend needs unrestricted host execution now refuse without a real sandbox adapter. The fabricated adapters were removed, not replaced with canned successes. The new external-source path is functional; the existing bounty, OSINT, sports, trading and Tor backend APIs are not silently declared compatible with it. Their command parsing/governance remains, and their synthetic unit tests now explicitly register offline fixtures. Restoring those live backends requires implementing their actual operations through approved source/broker interfaces.

## Other bugs fixed

The DAG executor now handles a worker denial without dereferencing it as a receipt or inventing an execution receipt. Kernel-issued scope information reaches the worker through signed token fields, including container-tier selection. Isolated Python uses the base interpreter with isolated/no-site startup, avoiding host virtualenv configuration reads. Audit fixtures explicitly declare offline behavior, so the matrix does not depend on production security exceptions.

## Verification and host limitations

Final verification: **445/445 tests pass in both environments** (`.venv`: 304.072s; `ciph_env`: 262.500s), including **42 Phase 7 tests**. Both standalone audits pass: **16/16 governance fixtures** and **25/25 command checks**. All **166 Python sources compile**, and their hashes match both final tested snapshots. [Verification results](PHASE7_VERIFICATION_RESULTS.json) include exact source/artifact hashes and saved logs under `verification/phase7/`.

A separate live check made one bounded, scoped HTTPS request to `https://check.torproject.org/api/ip` through the new broker. The receipt signature verified, the endpoint reported `IsTor=true`, and the resulting claim remained `OBSERVED` with assurance 0.40. The summary retains the observation digest without publishing the exit IP: [live check](verification/phase7/live-tor-results.json).

Tests run in source-only temporary workspaces with disposable databases and canaries. The development vault, keys and credentials are not used. No persistent service is started and nothing is staged or committed. Regression suites use synthetic local peers; the separately recorded live check is the single public diagnostic request described above.

The dedicated suite verifies both real kernel confinement and a local synthetic SOCKS peer. The peer exercises the wire protocol, DNS/IP binding, SSRF rejection, bounded responses, receipt signing, observation ingestion and replay; it never contacts the Internet and does not certify a live Tor circuit.

On this host, disposable-process containment works. Bubblewrap currently refuses namespace setup with `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`. An additional disposable probe retaining kernel socket denial but avoiding loopback setup also failed with `bwrap: setting up uid map: Permission denied`. The production configuration was not weakened. The container tier's safe-refusal path is verified; successful container execution remains a host-dependent acceptance gate. No host security settings were weakened to bypass this restriction.

The capability matrix remains an isolated control-flow audit. Test counts are regression evidence, not proof of universal containment or live-service availability. Deployment acceptance must separately demonstrate a working rootless-container boundary on an enabled host before the rootless tier can be certified. The separately scoped real Tor diagnostic passed; that single check does not certify every external provider or legacy backend.

Repository hygiene: no changes were staged or committed. The broad `git diff --check` still reports pre-existing trailing whitespace in tracked legacy files that were already modified on entry; those unrelated files were not reformatted as part of Phase 7.
