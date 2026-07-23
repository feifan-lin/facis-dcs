"""Wallet leg of the signing ceremony: presents a pre-issued EUDI PID SD-JWT plus
a PoA SD-JWT over OpenID4VP direct_post.

The PID must already exist. This helper only attaches a fresh KB-JWT for the
ceremony nonce/aud.

Usage:
  python3 complete_signing_webhook.py <openid4vp://... | request_uri> --pid-jwt PATH
  E2E_PID_JWT=PATH python3 complete_signing_webhook.py <openid4vp://...>

Env: STATUSLIST_SERVICE_URL, BDD_DCS_BASE_URL, E2E_PID_JWT
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
sys.path.insert(0, REPO_ROOT)

from steps.support import localhost_resolver  # noqa: E402

localhost_resolver.install()

import requests  # noqa: E402

from steps.support.api_client import did_document_url  # noqa: E402
from steps.support.services.auth_service import AuthCredentials, AuthService  # noqa: E402

PID_QUERY_ID = "eudi_pid_credential"
POA_QUERY_ID = "dcs_poa_credential"


def resolve_request_uri(pasted: str) -> str:
    pasted = pasted.strip()
    if not pasted:
        raise ValueError("empty presentation URL")
    if pasted.startswith("openid4vp:"):
        query = parse_qs(urlparse(pasted).query)
        request_uri = (query.get("request_uri") or [""])[0]
        if not request_uri:
            raise ValueError("openid4vp URL missing request_uri")
        return request_uri
    if pasted.startswith("http://") or pasted.startswith("https://"):
        return pasted
    raise ValueError(f"unsupported presentation URL: {pasted[:80]}")


def load_pid_sd_jwt(path: Path) -> str:
    raw = path.read_text(encoding="utf-8").strip()
    if not raw.startswith("eyJ"):
        raise ValueError(f"{path} must contain an SD-JWT (got {raw[:32]!r})")
    return raw


def wait_until_pid_nbf(sd_jwt: str, *, skew_seconds: float = 1.0) -> None:
    """EUDI pid-issuer sets nbf = iat + ~20s; presenting earlier fails verification."""
    AuthService._ensure_dcs_wallet_importable()
    from dcs_wallet.credential import decode_jwt_payload
    from dcs_wallet.sdjwt import split_sd_jwt

    issuer_jwt, _, _ = split_sd_jwt(sd_jwt)
    claims = decode_jwt_payload(issuer_jwt)
    nbf = claims.get("nbf")
    if nbf is None:
        return
    nbf_ts = float(nbf)
    delay = nbf_ts + skew_seconds - time.time()
    if delay > 0:
        time.sleep(delay)


def present_eudi_pid(*, sd_jwt: str, aud: str, nonce: str) -> str:
    AuthService._ensure_dcs_wallet_importable()
    from dcs_wallet.presentation import build_vp_token_from_sd_jwt

    return build_vp_token_from_sd_jwt(sd_jwt, nonce=nonce, client_id=aud)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("wallet_uri", help="openid4vp://... or request_uri URL")
    parser.add_argument(
        "--pid-jwt",
        dest="pid_jwt",
        default=os.environ.get("E2E_PID_JWT", "").strip(),
        help="Path to a pre-issued EUDI PID SD-JWT (or set E2E_PID_JWT)",
    )
    args = parser.parse_args()
    if not args.pid_jwt:
        raise SystemExit(
            "EUDI PID SD-JWT required: pass --pid-jwt PATH or set E2E_PID_JWT "
            "(issue via testWallet/scripts/issue_pid_credentials.py against the local pid-issuer)"
        )

    pid_path = Path(args.pid_jwt).expanduser().resolve()
    if not pid_path.is_file():
        raise SystemExit(f"PID JWT not found: {pid_path}")

    base_url = os.environ["BDD_DCS_BASE_URL"].rstrip("/")
    poa_organization = requests.get(did_document_url(base_url), timeout=30).json()["id"]

    request_uri = resolve_request_uri(args.wallet_uri)
    session = requests.Session()
    auth_request = AuthService.fetch_authorization_request(session, request_uri, timeout=60)

    pid_sd_jwt = load_pid_sd_jwt(pid_path)
    wait_until_pid_nbf(pid_sd_jwt)
    pid_vp = present_eudi_pid(
        sd_jwt=pid_sd_jwt,
        aud=auth_request.client_id,
        nonce=auth_request.nonce,
    )
    poa_vp = AuthService.build_vp_token(
        AuthCredentials(organization=poa_organization, roles=["Contract Signer"]),
        nonce=auth_request.nonce,
        client_id=auth_request.client_id,
    )
    vp_token = json.dumps(
        {PID_QUERY_ID: [pid_vp], POA_QUERY_ID: [poa_vp]},
        separators=(",", ":"),
    )
    response = session.post(
        auth_request.response_uri,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={"state": auth_request.state, "vp_token": vp_token},
        timeout=60,
    )
    if not response.ok:
        # Surface WHAT the ceremony refused (e.g. which PoA organization was
        # presented versus the party the ceremony is bound to); raise_for_status
        # alone reports only the code, which says nothing about the mismatch.
        raise SystemExit(
            f"direct_post {response.status_code} for {auth_request.response_uri}\n"
            f"  pid_jwt={pid_path}\n"
            f"  presented poa_organization={poa_organization!r}\n"
            f"  response: {response.text[:600]}"
        )
    print(response.status_code, response.text[:500])


if __name__ == "__main__":
    main()
