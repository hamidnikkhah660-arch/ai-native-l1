#!/usr/bin/env python3
"""Railway entrypoint for one QFP6 zero-value Public Testnet node.

No private key is baked into the image or written to the volume. Each Railway
service receives unique stable key material through its own service secrets.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

APP = Path("/app")
ASSETS = APP / "assets"
DATA = Path("/data")
CONFIG_DIR = DATA / "config"
CONFIG = CONFIG_DIR / "node-config.json"
CONFIG_HASH = CONFIG_DIR / "node-config.json.sha256"
BOOTSTRAP = DATA / "bootstrap-peers.json"

NETWORK_ID = "633b5dfc16fb2ec1825baf924ae7f7f16bf2006f8b64441a57692a3531722712"
PROFILE_ID = "a0a057d72c11253386bfe90d428bccbc44ebc86fc84e04e3682193a99d8805c4"
PROFILE_COMMITMENT = "a5707de437cf461f1a775a3d5a92d619955af35736ba54b609012a9446701d3e"
SOFTWARE_KEY_ACK = "SOFTWARE_KEY_CUSTODY_ZERO_VALUE_TESTNET_ONLY"


def require_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"required Railway variable {name} is missing")
    return value


def trusted_manifest_anchor_from_env() -> str | None:
    """Read the operator-pinned public root anchor without deriving it from node data.

    QFP6_TRUSTED_MANIFEST_ANCHOR is a 32-byte public commitment, not a signing key.
    It must be independently verified against the node's immutable sequence-1 vault
    record before being provisioned as a Railway service-level variable.
    """
    value = os.environ.get("QFP6_TRUSTED_MANIFEST_ANCHOR", "").strip()
    if not value:
        return None
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise RuntimeError(
            "QFP6_TRUSTED_MANIFEST_ANCHOR must be exactly 64 lowercase hexadecimal characters"
        )
    if value == "0" * 64:
        raise RuntimeError("QFP6_TRUSTED_MANIFEST_ANCHOR must not be zero")
    return value


def trusted_manifest_floor_from_env() -> tuple[int, str] | None:
    """Read an independently retained minimum generation/anchor checkpoint."""
    generation_text = os.environ.get("QFP6_TRUSTED_MANIFEST_FLOOR_GENERATION", "").strip()
    anchor = os.environ.get("QFP6_TRUSTED_MANIFEST_FLOOR_ANCHOR", "").strip()
    if not generation_text and not anchor:
        return None
    if not generation_text or not anchor:
        raise RuntimeError(
            "QFP6_TRUSTED_MANIFEST_FLOOR_GENERATION and "
            "QFP6_TRUSTED_MANIFEST_FLOOR_ANCHOR must be set together"
        )
    if (
        not generation_text.isascii()
        or not generation_text.isdigit()
        or (len(generation_text) > 1 and generation_text.startswith("0"))
    ):
        raise RuntimeError(
            "QFP6_TRUSTED_MANIFEST_FLOOR_GENERATION must be canonical unsigned decimal"
        )
    if len(generation_text) > 20:
        raise RuntimeError("QFP6_TRUSTED_MANIFEST_FLOOR_GENERATION exceeds u64")
    generation = int(generation_text)
    if generation > (1 << 64) - 1:
        raise RuntimeError("QFP6_TRUSTED_MANIFEST_FLOOR_GENERATION exceeds u64")
    if len(anchor) != 64 or any(ch not in "0123456789abcdef" for ch in anchor):
        raise RuntimeError(
            "QFP6_TRUSTED_MANIFEST_FLOOR_ANCHOR must be exactly 64 lowercase hexadecimal characters"
        )
    if anchor == "0" * 64:
        raise RuntimeError("QFP6_TRUSTED_MANIFEST_FLOOR_ANCHOR must not be zero")
    return generation, anchor


def select_storage_layout(role: str) -> str:
    """Preserve an existing v3/v4 data layout; refuse ambiguous mixed layouts."""
    existing_versions: list[str] = []
    for version in ("v3", "v4"):
        paths = (
            DATA / f"node-data-{role}-{version}",
            DATA / f"mempool-{role}-{version}",
            DATA / f"q6pd-{role}-{version}",
            DATA / f"anchor-vault-{role}-{version}",
        )
        found = False
        for path in paths:
            if not os.path.lexists(path):
                continue
            if path.is_symlink() or not path.is_dir():
                raise RuntimeError(
                    f"QFP6 {version} storage path must be a real directory: {path.name}"
                )
            found = True
        if found:
            existing_versions.append(version)

    if len(existing_versions) > 1:
        raise RuntimeError(
            f"ambiguous QFP6 storage layouts for {role}: v3 and v4 both exist; "
            "refusing to ignore or combine durable history"
        )
    return existing_versions[0] if existing_versions else "v4"


def resolve_public_proxy_endpoint(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text.isdigit():
        raise RuntimeError("QFP6_ADVERTISE_PROXY_ENDPOINT must be hostname:port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise RuntimeError("QFP6_ADVERTISE_PROXY_ENDPOINT port is out of range")

    answers = socket.getaddrinfo(host, port, family=socket.AF_INET, type=socket.SOCK_STREAM)
    rejected: list[str] = []
    for answer in answers:
        address = ipaddress.ip_address(answer[4][0])
        if address.is_global and not address.is_multicast:
            return str(address), port
        rejected.append(str(address))
    raise RuntimeError(
        "Railway TCP proxy did not resolve to a globally routable IPv4 address; "
        f"advertised candidates were {', '.join(rejected) or 'none'}"
    )


def artifact(name: str) -> str:
    candidate = ASSETS / name
    if not candidate.is_file():
        raise RuntimeError(f"required QFP6 testnet artifact is missing: {candidate}")
    return str(candidate)


def build_config(role: str) -> tuple[dict, bytes]:
    role = role.lower()
    if role not in {"seed", "relay", "joiner"}:
        raise RuntimeError("QFP6_NODE_ROLE must be seed, relay, or joiner")

    # Validate this external pin before writing bootstrap/config files. Absence is
    # allowed for genuinely fresh Genesis state; existing history will fail closed.
    configured_root_anchor = trusted_manifest_anchor_from_env()
    configured_floor = trusted_manifest_floor_from_env()
    if (configured_root_anchor is None) != (configured_floor is None):
        raise RuntimeError(
            "QFP6_TRUSTED_MANIFEST_ANCHOR and the external manifest floor must be provisioned together"
        )

    is_seed = role == "seed"
    is_relay = role == "relay"
    is_public = is_seed or is_relay

    peers: list[dict] = []
    if not is_seed:
        peer_address = require_env("QFP6_BOOTSTRAP_ADDRESS")
        peer_key = require_env("QFP6_BOOTSTRAP_NOISE_STATIC_PUBLIC_KEY").lower()
        if len(peer_key) != 64 or any(ch not in "0123456789abcdef" for ch in peer_key):
            raise RuntimeError("QFP6_BOOTSTRAP_NOISE_STATIC_PUBLIC_KEY must be 32-byte lowercase hex")
        peers.append({
            "address": peer_address,
            "noise_static_public_key": peer_key,
        })

    advertise_endpoint = None
    if is_public:
        ip, port = resolve_public_proxy_endpoint(require_env("QFP6_ADVERTISE_PROXY_ENDPOINT"))
        advertise_endpoint = f"{ip}:{port}"

    # Resolve the durable layout before writing any generated bootstrap/config files.
    # Mixed or unsafe paths must fail before even non-chain runtime state is changed.
    layout_version = select_storage_layout(role)

    BOOTSTRAP.parent.mkdir(parents=True, exist_ok=True)
    bootstrap_bytes = (json.dumps(peers, separators=(",", ":")) + "\n").encode("utf-8")
    BOOTSTRAP.write_bytes(bootstrap_bytes)
    bootstrap_sha = hashlib.sha256(bootstrap_bytes).hexdigest()

    node_data = DATA / f"node-data-{role}-{layout_version}"
    mempool_data = DATA / f"mempool-{role}-{layout_version}"
    q6pd_data = DATA / f"q6pd-{role}-{layout_version}"
    anchor_vault = DATA / f"anchor-vault-{role}-{layout_version}"
    node_data.mkdir(parents=True, exist_ok=True)
    mempool_data.mkdir(parents=True, exist_ok=True)
    q6pd_data.mkdir(parents=True, exist_ok=True)
    # Do NOT pre-create the anchor-vault directory. A fresh Joining node must
    # see it as absent so the runtime can provision the Genesis-rooted vault
    # atomically. An existing empty vault is correctly rejected as corruption.
    (DATA / "keys").mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    runtime = {
        "mode": "public-testnet-zero-value-candidate",
        "allow_candidate_runtime": True,
        "allow_public_listener": True,
        "listen_address": "0.0.0.0:31000" if is_public else "127.0.0.1:31000",
        "node_role": "seed" if is_seed else "joining",
        "data_directory": str(node_data),
        "mempool_directory": str(mempool_data),
        "bootstrap_peers_path": str(BOOTSTRAP),
        "bootstrap_peers_sha256": bootstrap_sha,
        "genesis_snapshot_path": artifact("genesis-snapshot.q6sn"),
        "genesis_snapshot_sha256": "6961e7517adcb66c04a3c566ec8c5cba398940eb273eabd082b706bb32a4f757",
        "q6cp_profile_path": artifact("consensus-profile.q6cp"),
        "q6cp_profile_sha256": "0ff4786c2b62228883699c687b34d57a85f3bcddde9a545c95f5515a388c516f",
        "q6gd_descriptor_path": artifact("genesis-descriptor.q6gd"),
        "q6gd_descriptor_sha256": "e5bbd024511f907d1e9bf3c1d4004d05851cd96c79eebd0f1ce446aee15a1888",
        "q6pn_profile_pin_path": artifact("q6pn-profile.q6pn"),
        "q6pn_profile_pin_sha256": "bb3d1e5710827afd8248292f9c19ab250dcdc8e508711597dd049c77a6ec8233",
        "q6pn_profile_pin_commitment": PROFILE_COMMITMENT,
        "public_testnet_authorization_path": artifact("public-testnet-authorization.q6ga"),
        "public_testnet_authorization_sha256": "72d58ef455d9b6f6ab9a5514f5f0fb40f333d347af288363b3897b5584c2f169",
        "public_testnet_acknowledgement": "ZERO_VALUE_PUBLIC_TESTNET_NO_MAINNET_NO_MARKET",
        "public_inbound_security_acknowledgement": "ANONYMOUS_NOISE_XX_UNAUTHENTICATED",
        "node_noise_private_key_path": "/data/keys/noise.npk",
        "trusted_manifest_anchor_vault_path": str(anchor_vault),
        "require_device_root_binding": False,
        "enable_q6pd_peer_discovery": True,
        "enable_q6pd_peer_pull": True,
        "enable_q6pd_self_announcement": is_public,
        "q6pd_peer_record_store_path": str(q6pd_data / "peer-record-store.json"),
        "enable_q6ar_candidate_address_book": False,
        "enable_q6ar_candidate_pull": False,
        "enable_peer_address_book": False,
        "enable_approved_peer_outbound_sync": False,
        "allow_software_testnet_key_custody": True,
        "software_testnet_key_custody_acknowledgement": SOFTWARE_KEY_ACK,
    }

    if not is_seed:
        # Only fresh zero-value Testnet Joiners may derive their own immutable local
        # sequence-1 vault root, and only after Q6PN/Q6GD/Q6GA and Genesis checks pass.
        # Existing history is still rejected by the runtime's generation/height gate.
        runtime["derive_fresh_joiner_anchor_from_verified_genesis"] = True
        runtime["fresh_genesis_anchor_derivation_acknowledgement"] = (
            "VERIFIED_GENESIS_DERIVED_ANCHOR_ZERO_VALUE_TESTNET_ONLY"
        )
    if configured_root_anchor is not None and configured_floor is not None:
        runtime["trusted_manifest_anchor"] = configured_root_anchor
        runtime["trusted_manifest_floor_generation"] = configured_floor[0]
        runtime["trusted_manifest_floor_anchor"] = configured_floor[1]
    if is_public:
        runtime["q6pd_self_advertise_endpoint"] = advertise_endpoint

    config = {"permissionless_runtime": runtime}
    config["public_testnet_notice"] = "ZERO_VALUE_PUBLIC_TESTNET_CANDIDATE_ONLY_NOT_MAINNET"
    return config, bootstrap_bytes


def main() -> int:
    role = require_env("QFP6_NODE_ROLE")
    config, _ = build_config(role)
    raw = (json.dumps(config, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    CONFIG.write_bytes(raw)
    digest = hashlib.sha256(raw).hexdigest()
    CONFIG_HASH.write_text(digest + "\n", encoding="ascii")

    # Validate configuration and all static trust pins before exposing the socket.
    # The launcher binds the listener only after cryptographic/state checks pass.
    binary = "/usr/local/bin/qrun_v06_node"
    command = [
        binary,
        "--public-testnet-run",
        "--config",
        str(CONFIG),
        "--config-sha256",
        digest,
    ]
    print(f"QFP6_RAILWAY_NODE_ROLE={role}", flush=True)
    print("QFP6_RAILWAY_PERSISTENT_VOLUME=/data", flush=True)
    print("QFP6_RAILWAY_SOFTWARE_KEY_CUSTODY=SERVICE_SCOPED_SECRETS", flush=True)
    print("QFP6_RAILWAY_VALUE_SCOPE=ZERO_VALUE_TESTNET_ONLY", flush=True)
    os.execv(binary, command)
    return 127


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"QFP6_RAILWAY_ENTRYPOINT_REFUSED={exc}", file=sys.stderr, flush=True)
        raise SystemExit(2)
