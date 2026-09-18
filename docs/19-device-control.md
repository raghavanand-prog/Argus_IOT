# 19 — Device control

A capability-based, explicitly-authorized device-control subsystem for devices the
project owner actually owns or administers — a projector, a smart display, a network
speaker — controlled through documented, real protocols. This is not an exploitation
feature: no credential brute-forcing, no bypassing authentication, no arbitrary command
injection, no vulnerability exploitation. Every action requires the device to have a
real, detected, supported protocol, and requires the machine running the local sensor
to have explicitly authorized it first.

**Core rule, stated once and enforced in exactly one place**: a control command is
never executed because the cloud console says to. `sensor/control/registry.py::
execute_command()` re-checks the *local* authorization store on the machine actually
running the sensor, every single time, regardless of who's asking. See §4.

## 1. Architecture: why console buttons queue, they don't execute

Vercel cannot reach a private LAN (docs/18 §1). A naive "click button → cloud sends the
command" design simply cannot work — and building a UI that looks like it works while
silently doing nothing would itself be exactly the kind of fabrication this project's
core honesty rule forbids.

The resolution is a command-queue relay, the same pattern real cloud-to-home-hub
systems use (a smart-home hub polling its cloud service for pending commands):

```
Console click → POST /live/control/commands (queues an intent, status=pending)
                        ↓
Sensor's own poll loop (--enable-control, every ~30s)
  → GET /live/control/commands?sensor_id=...
  → for each command: execute_command() -- re-verifies against the LOCAL
    AuthorizationStore (~/.argus/authorized_devices.json) on THIS machine
  → only if authorized: real PJLink call to the real device
  → POST /live/control/commands/{id}/result
  → POST /live/control/report (new audit entries, current capability/auth mirror)
                        ↓
Console displays the result once the sensor has reported it
```

The cloud (`argus/control.py`, backing both `argus/api/main.py` locally and
`api/index.py` in production) is the authoritative **queue** — a click becomes a real
row with `status="pending"`. It is never the authority on whether a command is
**allowed**. A row it creates is a request, not a grant. This means device control is
never instantaneous from the console's perspective — a click queues, the sensor's next
poll (up to ~30s later) actually acts, and the console shows the result once reported.
The console UI states this plainly (see `console/src/pages/DeviceControl.tsx`'s banner)
rather than implying a live, instant action.

## 2. Discovery vs. capability probing vs. control — three different, deliberately
separated steps

1. **Discovery** (`sensor/discovery.py`, always passive): a device shows up with
   `device_type: "unknown"` and no control information at all. Nothing here implies
   controllability.
2. **Capability probing** (`sensor/control/registry.py::probe_capability`, explicit,
   single-device, user-requested only — `python -m sensor.control_cli
   discover-capability <ip>`): a single, minimal, protocol-legitimate TCP connection
   attempt on PJLink's standard port (4352) — the same thing any PJLink control app
   does to find controllable projectors. **Never run automatically against every
   discovered device** — that would be a network-wide scan, explicitly ruled out by
   this project's safety requirements. A device that doesn't answer with a real PJLink
   greeting is reported honestly as unsupported, never guessed at.
3. **Authorization** (`python -m sensor.control_cli authorize <ip>`, local, explicit,
   human-in-the-loop): only after step 2 finds a real, supported protocol. A device is
   never auto-authorized. Revocable at any time (`revoke`).

Only after all three does a device's controls appear on the Device Control console
page.

## 3. PJLink: the one protocol implemented, implemented fully

[PJLink](https://pjlink.jbmia.or.jp/english/) (JBMIA's published, vendor-neutral
projector/display network control standard) is the protocol the project owner named
explicitly. `sensor/control/pjlink.py` implements PJLink Class 1 — power, input
select, audio/video mute, status queries, and the MD5-challenge authentication mode —
against the real wire protocol (TCP port 4352, real greeting parsing, real MD5
challenge-response), not a stub.

**Tested, honestly**: `tests/control/mock_pjlink_server.py` is a real TCP server
speaking the real PJLink protocol (both no-auth and MD5-auth-challenge modes),
against which `PJLinkClient`'s request/response handling, error mapping, and
capability probing are all verified with real socket round-trips (13 tests,
`tests/control/test_pjlink.py`). **What this does not verify**: no real projector
hardware was available this session, so the client has never actually been run
against physical PJLink-capable hardware. The protocol itself is faithfully
implemented against its published spec; hardware verification is the one honest gap
remaining, named here rather than glossed over.

**Not implemented**: PJLink Class 2 (extended commands), vendor-specific display
APIs, UPnP/SSDP-based control, any other protocol the spec's §5 lists as an example.
The capability-probing framework (`probe_capability`/`execute_command`) is built to
add another protocol without changing its shape, but only PJLink is real today. A
device with no PJLink response is reported as `"Control support: Not available"` —
never a fabricated capability.

## 4. The one enforcement checkpoint

`sensor/control/registry.py::execute_command()` is the single place any control
action — from the local CLI, or fulfilling a cloud-queued command — passes through:

1. Look up the device in the **local** `AuthorizationStore`. Not authorized → `DENIED`,
   audited, nothing else happens. This check runs identically regardless of who's
   asking; `requested_by="cloud-console"` and `requested_by="local-cli"` get the exact
   same scrutiny.
2. Action not in the supported set → `FAILURE`, audited.
3. Device's protocol has no control implementation (anything but `"pjlink"` today) →
   `FAILURE`, audited.
4. Only then: fetch the device's stored credential (if any,
   `sensor/control/credentials.py`), make the real PJLink call, record the real
   outcome.

Every path — success, failure, or denial — writes a `ControlAuditEntry`. An audit log
that only records successes isn't an audit trail; a denied attempt is exactly the kind
of thing worth being able to review later.

Verified with a real test simulating the actual attack scenario this design defends
against (`tests/control/test_registry.py::
test_execute_command_denied_even_when_cloud_claims_authorization`): calling
`execute_command` for a device that was never locally authorized, with
`requested_by="cloud-console"`, is denied — the function has no code path that trusts
a caller's claim of authorization.

## 5. Storage: local, not cloud (explicit project-owner decision)

- **Authorization** (`sensor/control/authorization.py`): `~/.argus/authorized_devices.json`,
  atomic-write JSON, on the machine running the sensor. The cloud API (`argus.control`)
  mirrors a *read-only* copy of protocol/capabilities/authorized state into
  `LiveDeviceRow` purely for console display — the mirror is never consulted by
  `execute_command`.
- **Credentials** (`sensor/control/credentials.py`): the OS keychain (macOS Keychain,
  via the `keyring` package) when available — genuinely never written to disk in
  plaintext. Falls back to `~/.argus/credentials.json` with owner-only (`chmod 600`)
  permissions when no OS keyring service is available (confirmed in this sandbox: no
  D-Bus Secret Service, so `keyring.get_keyring()` returns the `fail` backend — a real,
  honestly-documented, weaker-guarantee fallback, not a silent downgrade). Never in the
  repository, never logged, never sent to the frontend.
- **Audit log** (`sensor/control/audit.py`): `~/.argus/control_audit.jsonl`,
  append-only. The source of truth; the cloud's `ControlAuditRow` table is a display
  mirror, reported via `/live/control/report`.

This was an explicit choice (over a cloud-DB-backed authorization system) made by the
project owner this session: the machine with actual LAN access is the one that
decides, and enforces, whether it will act on a device — never the cloud API, which
has no way to verify a claim about physical network access anyway.

## 6. Kill switch scope (verified in code, not just documented)

The kill switch (`argus.respond.guard.KillSwitch`) gates exactly one thing: whether
`decide_and_respond` — the *autonomous* incident-response ladder — is allowed to act.
Grepping the codebase confirms `kill_switch` is referenced only in
`argus/respond/guard.py` and `argus/respond/ladder.py`; `sensor/control/registry.py`
(the manual Device Control execution path) has zero references to it. This isn't a
documentation claim layered on top — the kill switch and Device Control are two
structurally separate systems that happen to share no code path:

- **Kill switch engaged** → autonomous response to a *detected threat* is blocked.
  Detection, monitoring, evidence collection, and audit logging all continue
  unaffected (unchanged from docs/03's original design).
- **Device Control** → a human, at the machine running the sensor, explicitly
  authorizing and then explicitly confirming a specific action against a specific
  device they administer. This was never "autonomous" to begin with, so the kill
  switch has nothing to gate here — engaging it does not block a Device Control
  action, and that is correct, not an oversight: they answer different questions
  ("should ARGUS react on its own to what it detected?" vs. "should this specific,
  human-approved command to a device I own go through?").

## 7. Confirmation and safety

Disruptive actions (`power_on`, `power_off`, `mute_on`, `mute_off`) require explicit
confirmation before being queued — both in the CLI (`sensor/control_cli.py`'s `y/N`
prompt, skippable with `--yes` for scripting) and in the console
(`DeviceControl.tsx`'s confirmation dialog, naming the exact device and IP). Read-only
queries (`get_status`) need none.

## 8. What's not built

- Only PJLink; no other protocol (see §3).
- No hardware verification (see §3) — the client is protocol-correct against a real
  mock server, not proven against physical devices.
- No cloud-side authorization override for a locked-out sensor (by design — see §5).
- No automatic re-probing of a device's capability over time; `discover-capability`
  is a point-in-time, explicit check.
