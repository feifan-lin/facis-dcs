#!/usr/bin/env python3
"""Print an OID4VCI Credential Offer URI from the local EUDI PID Issuer.

The offer uses authorization_code (not pre-authorized), so it is not bound to a
Keycloak user. After opening/scanning the offer, log in as the holder
(default hint: alicewilliams / alicewilliams).

Example:
  python testWallet/scripts/show_pid_offer_url.py
  python testWallet/scripts/show_pid_offer_url.py --user alicewilliams
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

DEFAULT_ISSUER = "http://localhost:30880"
DEFAULT_CONFIG_ID = "eu.europa.ec.eudi.pid_vc_sd_jwt"
DEFAULT_USER = "alicewilliams"


def _post_json(url: str, body: dict) -> dict:
    raw = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=raw,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code} for {url}: {detail[:500]}") from exc


def create_offer(issuer: str, config_id: str) -> str:
    url = f"{issuer.rstrip('/')}/issuer/credentialsOffer/create"
    data = _post_json(url, {"credentialIds": [config_id]})
    offer = data.get("credentialsOffer")
    if not isinstance(offer, str) or not offer.strip():
        raise RuntimeError(f"unexpected offer response: {data}")
    return offer.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Print PID issuance offer URI")
    parser.add_argument("--issuer", default=DEFAULT_ISSUER)
    parser.add_argument("--config-id", default=DEFAULT_CONFIG_ID)
    parser.add_argument(
        "--user",
        default=DEFAULT_USER,
        help="Keycloak username hint after opening the offer (password defaults to username)",
    )
    parser.add_argument("--password", help="Login password hint (default: same as --user)")
    args = parser.parse_args()

    password = args.password or args.user
    offer = create_offer(args.issuer, args.config_id)

    print(f"holder_login_user={args.user}")
    print(f"holder_login_password={password}")
    print(f"credential_configuration_id={args.config_id}")
    print(offer)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
