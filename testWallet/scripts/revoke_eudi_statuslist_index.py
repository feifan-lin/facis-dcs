#!/usr/bin/env python3
"""Dev helper: revoke an EUDI Token Status List index (pid-issuer / eudi-srv-statuslist-py).

Uses the EUDI statuslist revoke endpoint (same as pid-issuer ISSUER_STATUSLIST_SERVICE_REVOKE_URI):
  POST /token_status_list/set
  form: uri=<status list uri>  idx=<index>  status=1
  header: X-Api-Key: <api key>

Defaults match values.dev.yml (NodePort 30822, api key dev-eudi-statuslist-api-key).

To look up idx/uri, paste the PID SD-JWT into https://www.sdjwt.co/ and read
status.status_list.{idx,uri}, or pass --credential.

Examples:
  python testWallet/scripts/revoke_eudi_statuslist_index.py --credential credentials/johndoe.pid.jwt
  python testWallet/scripts/revoke_eudi_statuslist_index.py 42 \\
    --uri http://localhost:30822/token_status_list/FC/urn:eudi:pid:1/abc123
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

WALLET_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WALLET_ROOT))

from dcs_wallet.credential import decode_jwt_payload
from dcs_wallet.sdjwt import split_sd_jwt
from dcs_wallet.status_list import (
    _decompress_bitstring,
    bit_is_revoked,
    credential_status_from_claims,
    encoded_list_from_payload,
)

DEFAULT_SERVICE_BASE = "http://localhost:30822"
DEFAULT_API_KEY = "dev-eudi-statuslist-api-key"


def _resolve_credential_path(path: Path) -> Path:
    """Resolve --credential; bare relative paths try cwd then testWallet/."""
    if path.is_file():
        return path
    under_wallet = WALLET_ROOT / path
    if under_wallet.is_file():
        return under_wallet
    raise FileNotFoundError(
        f"credential not found: {path} (also tried {under_wallet})"
    )


def _index_from_credential(path: Path) -> tuple[int, str]:
    path = _resolve_credential_path(path)
    raw = path.read_text(encoding="utf-8").strip()
    issuer_jwt, _, _ = split_sd_jwt(raw)
    claims = decode_jwt_payload(issuer_jwt)
    parsed = credential_status_from_claims(claims)
    if parsed is None:
        raise ValueError(f"{path.name}: missing status.status_list.{{idx,uri}}")
    return parsed


def _service_base_from_uri(status_uri: str) -> str:
    parsed = urlparse(status_uri.strip())
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"invalid status list uri: {status_uri}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _set_url(service_base: str) -> str:
    return f"{service_base.rstrip('/')}/token_status_list/set"


def _get_url(service_base: str) -> str:
    return f"{service_base.rstrip('/')}/token_status_list/get"


def revoke_eudi_index(
    *,
    idx: int,
    status_uri: str,
    api_key: str,
    service_base: str | None = None,
    timeout: float = 15.0,
) -> str:
    """POST form-urlencoded revoke (status=1). Returns response body text."""
    if idx < 0:
        raise ValueError(f"index must be non-negative, got {idx}")
    base = (service_base or _service_base_from_uri(status_uri)).rstrip("/")
    body = urlencode(
        {
            "uri": status_uri,
            "idx": str(idx),
            "status": "1",
        }
    ).encode("utf-8")
    req = Request(
        _set_url(base),
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json, text/plain, */*",
            "X-Api-Key": api_key,
        },
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"EUDI set failed HTTP {exc.code}: {detail}") from exc


def fetch_eudi_index_status(
    *,
    idx: int,
    status_uri: str,
    service_base: str | None = None,
    timeout: float = 15.0,
) -> int:
    """GET /token_status_list/get — returns integer status (0 active, 1 revoked)."""
    base = (service_base or _service_base_from_uri(status_uri)).rstrip("/")
    qs = urlencode({"uri": status_uri, "idx": str(idx)})
    req = Request(
        f"{_get_url(base)}?{qs}",
        headers={"Accept": "application/json, text/plain, */*"},
    )
    with urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace").strip().strip('"')
    try:
        return int(raw, 10)
    except ValueError as exc:
        raise RuntimeError(f"unexpected get response: {raw!r}") from exc


def fetch_eudi_status_list_jwt(status_uri: str, timeout: float = 15.0) -> dict:
    """Fetch Token Status List JWT and return decoded payload claims."""
    req = Request(
        status_uri,
        headers={"Accept": "application/statuslist+jwt"},
    )
    with urlopen(req, timeout=timeout) as resp:
        token = resp.read().decode("utf-8", errors="replace").strip()
    return decode_jwt_payload(token)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Revoke an EUDI Token Status List index (dev)",
        epilog=(
            "Look up idx/uri: paste the PID SD-JWT into https://www.sdjwt.co/ "
            "and read status.status_list, or use --credential."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "index",
        nargs="?",
        help="status_list.idx to revoke (or use --credential)",
    )
    parser.add_argument(
        "--credential",
        type=Path,
        help="PID SD-JWT file; reads status.status_list.{idx,uri}",
    )
    parser.add_argument(
        "--uri",
        help="status_list.uri (required unless --credential)",
    )
    parser.add_argument(
        "--service-base",
        default=os.getenv("EUDI_STATUSLIST_SERVICE_URL", ""),
        help=(
            "statuslist root URL (default: derived from --uri, or "
            f"EUDI_STATUSLIST_SERVICE_URL, else {DEFAULT_SERVICE_BASE})"
        ),
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("EUDI_STATUSLIST_API_KEY", DEFAULT_API_KEY),
        help=(
            "X-Api-Key for /set "
            f"(default: EUDI_STATUSLIST_API_KEY or {DEFAULT_API_KEY})"
        ),
    )
    args = parser.parse_args()

    if args.credential is not None:
        idx, status_uri = _index_from_credential(args.credential)
        if args.index is not None and str(args.index) != str(idx):
            print(
                f"warning: CLI index {args.index} differs from credential index {idx}; using credential",
                file=sys.stderr,
            )
        if args.uri and args.uri.strip() != status_uri:
            print(
                "warning: CLI --uri differs from credential uri; using credential",
                file=sys.stderr,
            )
    else:
        if args.index is None or not args.uri:
            parser.error("provide index + --uri, or --credential")
        idx = int(args.index, 10)
        status_uri = args.uri.strip()

    service_base = (args.service_base or "").strip() or _service_base_from_uri(status_uri)

    print(f"POST set idx={idx} status=1")
    print(f"  uri={status_uri}")
    print(f"  service={service_base}")
    result = revoke_eudi_index(
        idx=idx,
        status_uri=status_uri,
        api_key=args.api_key,
        service_base=service_base,
    )
    if result.strip():
        print("response:", result.strip())

    get_status = fetch_eudi_index_status(
        idx=idx,
        status_uri=status_uri,
        service_base=service_base,
    )
    print(
        f"verified (GET /token_status_list/get): idx={idx} -> status={get_status} "
        f"({'revoked' if get_status == 1 else 'active' if get_status == 0 else 'other'})"
    )

    jwt_revoked: bool | None = None
    try:
        claims = fetch_eudi_status_list_jwt(status_uri)
        encoded = encoded_list_from_payload(claims)
        jwt_revoked = bit_is_revoked(encoded, idx)
        bitstring = _decompress_bitstring(encoded)
        byte_idx = idx // 8
        byte_val = bitstring[byte_idx] if byte_idx < len(bitstring) else 0
        print(
            f"verified (statuslist+jwt LSB): index={idx} -> "
            f"{'revoked' if jwt_revoked else 'active'} "
            f"(byte[{byte_idx}]=0x{byte_val:02x})"
        )
    except Exception as exc:  # noqa: BLE001
        print(f"warning: could not verify via statuslist JWT: {exc}", file=sys.stderr)

    ok = get_status == 1 and (jwt_revoked is None or jwt_revoked)
    if not ok:
        print(
            "  revoke may not have persisted — check API key, uri, or statuslist logs",
            file=sys.stderr,
        )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
