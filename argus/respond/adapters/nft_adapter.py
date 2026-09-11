"""Real nftables-backed enforcement, scoped to the live network-namespace testbed
(argus/testbed/). This is the adapter docs/10 describes: "drop/reject rules in a
dedicated argus table so ARGUS's rules are always distinguishable from the system's
and can be flushed wholesale by the kill switch."

Why the ``bridge`` table family, not ``inet``/``ip``: argus/testbed/fabric.py
disables ``bridge-nf-call-iptables`` so the testbed's L2-bridged traffic bypasses
the host's Docker-managed iptables FORWARD chain (see decisions.md) -- but that same
sysctl also means bridged frames never reach the ``inet``/``ip`` family's forward
hook. nftables' ``bridge`` family filters at the bridging layer directly,
independent of that sysctl, which is the only hook that actually sees this traffic.
This is not a workaround -- filtering bridged L2 traffic with the bridge family is
the documented, correct way to do it; matching packet IP/port fields still works
inside a bridge-family rule (nftables inspects the encapsulated headers).

Why rate-limiting uses ``nft limit rate over ... drop`` instead of ``tc`` HTB
shaping: ``tc``/iproute2 is not installed in this environment and cannot be (no
apt/package-mirror access -- see decisions.md). ``nft``'s own rate limiter drops
packets exceeding a threshold, which is a real, verifiable substitute for shaping,
though it drops rather than queues/delays -- stated as a scope difference from
docs/03's original ``tc``-based design, not hidden.
"""

from __future__ import annotations

import logging
import re
import subprocess

logger = logging.getLogger(__name__)

TABLE_FAMILY = "bridge"
TABLE_NAME = "argus"
CHAIN_NAME = "forward"


class NftablesError(RuntimeError):
    pass


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(["nft", *args], capture_output=True, text=True)
    if check and result.returncode != 0:
        raise NftablesError(f"nft {' '.join(args)} failed: {result.stderr.strip()}")
    return result


def ensure_table() -> None:
    """Idempotent: create the dedicated argus table + forward chain if absent."""
    existing = _run("list", "tables", check=False).stdout
    if f"table {TABLE_FAMILY} {TABLE_NAME}" not in existing:
        _run("add", "table", TABLE_FAMILY, TABLE_NAME)
    chains = _run("list", "table", TABLE_FAMILY, TABLE_NAME, check=False).stdout
    if f"chain {CHAIN_NAME}" not in chains:
        _run("add", "chain", TABLE_FAMILY, TABLE_NAME, CHAIN_NAME,
             "{", "type", "filter", "hook", "forward", "priority", "0", ";", "}")


def flush_all() -> None:
    """The kill-switch equivalent for live enforcement: deletes the entire argus
    table in one call. Idempotent -- deleting an absent table is a no-op, not an
    error, so this is always safe to call."""
    _run("delete", "table", TABLE_FAMILY, TABLE_NAME, check=False)


def _rule_handle_for(action_id: str) -> int | None:
    out = _run("-a", "list", "table", TABLE_FAMILY, TABLE_NAME, check=False).stdout
    for line in out.splitlines():
        if f"argus:{action_id}" in line:
            m = re.search(r"# handle (\d+)", line)
            if m:
                return int(m.group(1))
    return None


class NftablesAdapter:
    """Real enforcement. Every rule this adapter installs is tagged with a comment
    (``argus:<action_id>``) so ``revert()`` can find and delete exactly that rule by
    its nftables-assigned handle, without touching anything else in the table --
    including rules a different action installed."""

    def __init__(self) -> None:
        ensure_table()

    def apply(self, action_id: str, tier: int, device_id: str, *, iface: str,
              dst_ip: str | None = None) -> dict:
        comment = f'comment "argus:{action_id}"'
        if tier == 4:  # isolate: drop everything to/from this device's own port
            _run("add", "rule", TABLE_FAMILY, TABLE_NAME, CHAIN_NAME,
                 "iifname", iface, "drop", *comment.split())
            rule = f"isolate {device_id} (iface {iface})"
        elif tier == 3 and dst_ip:  # block_destination: narrower, device keeps other function
            _run("add", "rule", TABLE_FAMILY, TABLE_NAME, CHAIN_NAME,
                 "iifname", iface, "ip", "daddr", dst_ip, "drop", *comment.split())
            rule = f"block {device_id} -> {dst_ip} (iface {iface})"
        elif tier == 2:  # rate_limit: drop packets over a real threshold
            _run("add", "rule", TABLE_FAMILY, TABLE_NAME, CHAIN_NAME,
                 "iifname", iface, "limit", "rate", "over", "5/second", "drop", *comment.split())
            rule = f"rate-limit {device_id} (iface {iface})"
        else:
            raise ValueError(f"NftablesAdapter has no real rule for tier {tier} (only 2/3/4 touch the network)")

        logger.info("nft rule installed: %s", rule)
        return {"action_id": action_id, "tier": tier, "device_id": device_id, "dry_run": False, "rule": rule}

    def revert(self, action_id: str) -> dict:
        handle = _rule_handle_for(action_id)
        if handle is None:
            return {"action_id": action_id, "reverted": False, "reason": "rule not found (already reverted?)"}
        _run("delete", "rule", TABLE_FAMILY, TABLE_NAME, CHAIN_NAME, "handle", str(handle))
        logger.info("nft rule reverted: action_id=%s handle=%s", action_id, handle)
        return {"action_id": action_id, "reverted": True, "dry_run": False}

    def list_active(self) -> list[str]:
        out = _run("list", "table", TABLE_FAMILY, TABLE_NAME, check=False).stdout
        return [line.strip() for line in out.splitlines() if "argus:" in line]
