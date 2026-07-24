#!/usr/bin/env python3
"""Issue PID SD-JWTs via local OID4VCI (EUDI pid-issuer + Keycloak).

This script targets **local / development** use with the DCS dev-stack.
It follows the OID4VCI authorization_code shape where practical, 
but it is **not** a full-fidelity OID4VCI wallet client: several steps
are adapted for headless automation and the local insecure issuer profile.

OID4VCI steps (for orientation):
  1. Discover credential issuer metadata
  2. Discover OAuth authorization server metadata
  3. Authorization Code + PKCE (+ DPoP on token)
  4. Nonce endpoint (DPoP)
  5. Credential endpoint with openid4vci-proof+jwt (DPoP)

Where the local stack diverges, this module still exposes a more
standards-oriented helper (for readability) and uses the development-oriented
path in the issuance entrypoints. See ``DEV_LOCAL_ADAPTATIONS``.

Usage:
  python3 testWallet/scripts/issue_pid_credentials.py
  python3 testWallet/scripts/issue_pid_credentials.py --credential johndoe
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.cookiejar
import json
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from jwt.algorithms import ECAlgorithm

WALLET_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(WALLET_ROOT))

from dcs_wallet.keys import load_json, private_key_material, public_key_material  # noqa: E402

DEFAULT_CREDENTIALS_DIR = WALLET_ROOT / "credentials"
DEFAULT_ISSUER = "http://localhost:30880"
DEFAULT_REALM = "http://localhost:30080/realms/gaia-x"
DEFAULT_CLIENT_ID = "pid-holder-python"
DEFAULT_REDIRECT_URI = "http://127.0.0.1:8765/callback"
DEFAULT_SCOPE = "openid eu.europa.ec.eudi.pid_vc_sd_jwt"
DEFAULT_CONFIG_ID = "eu.europa.ec.eudi.pid_vc_sd_jwt"
PID_VCT = "urn:eudi:pid:1"

# Keycloak gaia-x users with eid-holder-natural-person (+ PID attributes).
# password None => username-as-password.
PID_HOLDERS: dict[str, str | None] = {
    "alicewilliams": None,
    "bobjohnson": None,
    "charliebrown": None,
    "johndoe": None,
    "janesmith": None,
    "saoirseconrad": None,
}
PID_HOLDER_USERNAMES: frozenset[str] = frozenset(PID_HOLDERS)

# Development-oriented adaptations relative to a strict OID4VCI wallet client.
# Kept so headless issuance stays reliable against the local DCS stack.
DEV_LOCAL_ADAPTATIONS: tuple[str, ...] = (
    "Issuer metadata is loaded from the Spring base-path well-known URL "
    "(EUDI pid-issuer), not the RFC8414 host/path-insertion form.",
    "Credential/nonce endpoint hosts from metadata are rewritten onto the "
    "reachable issuer URL (dev NodePort or kind Traefik).",
    "Authorization/token endpoint hosts from Keycloak discovery are rewritten "
    "onto the explicit realm URL (avoids in-cluster names like dcs-keycloak).",
    "The authorization server is taken from an explicit realm URL rather than "
    "metadata authorization_servers.",
    "Token acquisition prefers Resource Owner Password + DPoP for headless runs; "
    "authorization_code + PKCE remains implemented as the browser-shaped path.",
    "DPoP requests retry once when the server supplies a DPoP-Nonce.",
    "Credential proofs use a locally generated key-attestation+jwt (TS3) suitable "
    "for the issuer insecure/dev profile, not a production wallet attestation.",
    "The synthetic attestation embeds a placeholder status_list URI.",
    "All holders share keys/wallet.jwk unless the caller supplies another key.",
)



# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _fetch(
    url: str,
    *,
    method: str = "GET",
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
    form: dict[str, str] | None = None,
    allow_redirects: bool = True,
) -> tuple[int, dict[str, str], bytes]:
    if form is not None:
        body = urllib.parse.urlencode(form).encode("utf-8")
        headers = dict(headers or {})
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    opener = urllib.request.build_opener(
        urllib.request.HTTPRedirectHandler() if allow_redirects else urllib.request.BaseHandler
    )
    try:
        with opener.open(req, timeout=60) as resp:
            return resp.status, {k.lower(): v for k, v in resp.headers.items()}, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, {k.lower(): v for k, v in exc.headers.items()}, exc.read()


def _fetch_json(url: str, **kwargs: Any) -> dict[str, Any]:
    status, _headers, raw = _fetch(url, **kwargs)
    if status >= 400:
        raise RuntimeError(f"HTTP {status} for {url}: {raw[:500]!r}")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"expected JSON object from {url}")
    return data


# ---------------------------------------------------------------------------
# Discovery — RFC8414-oriented helpers vs local-dev paths
# ---------------------------------------------------------------------------


def issuer_metadata_url_rfc8414(issuer_url: str) -> str:
    """OID4VCI / RFC8414-style: insert /.well-known/... between host and path."""
    parsed = urllib.parse.urlparse(issuer_url.rstrip("/"))
    path = parsed.path.lstrip("/")
    if path:
        return f"{parsed.scheme}://{parsed.netloc}/.well-known/openid-credential-issuer/{path}"
    return f"{parsed.scheme}://{parsed.netloc}/.well-known/openid-credential-issuer"


def issuer_metadata_url_base_path(issuer_url: str) -> str:
    """Local-dev: EUDI pid-issuer serves well-known under SPRING base path."""
    return f"{issuer_url.rstrip('/')}/.well-known/openid-credential-issuer"


def as_metadata_url_rfc8414(issuer_identifier: str) -> str:
    """RFC8414 OAuth AS metadata URL for an issuer identifier that has a path."""
    parsed = urllib.parse.urlparse(issuer_identifier.rstrip("/"))
    path = parsed.path.lstrip("/")
    if path:
        return f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-authorization-server/{path}"
    return f"{parsed.scheme}://{parsed.netloc}/.well-known/oauth-authorization-server"


def as_metadata_url_oidc(auth_server: str) -> str:
    """OIDC discovery (Keycloak native): {realm}/.well-known/openid-configuration."""
    return f"{auth_server.rstrip('/')}/.well-known/openid-configuration"


def rewrite_endpoint_onto_base(base_url: str, metadata_url: str) -> str:
    """Keep path/query from metadata; replace scheme/host with a reachable base.
    """
    base = urllib.parse.urlparse(base_url)
    meta = urllib.parse.urlparse(metadata_url)
    return urllib.parse.urlunparse(
        (base.scheme, base.netloc, meta.path, meta.params, meta.query, meta.fragment)
    )


def discover_issuer_metadata(issuer_url: str) -> dict[str, Any]:
    """Load credential issuer metadata.

    Standards-oriented alternative: GET issuer_metadata_url_rfc8414(issuer_url).
    Local-dev path: base-path well-known as served by EUDI pid-issuer.
    """
    return _fetch_json(issuer_metadata_url_base_path(issuer_url), headers={"Accept": "application/json"})


def discover_as_metadata(*, realm_url: str, issuer_meta: dict[str, Any]) -> dict[str, Any]:
    """Load authorization server metadata.

    A stricter client would use issuer_meta['authorization_servers'][0] + RFC8414 AS
    well-known (or OIDC discovery on that URL).
    Local-dev path: ignore metadata AS hostnames; use explicit realm_url (NodePort).
    """
    _ = issuer_meta  # available for a future standards-only mode
    return _fetch_json(as_metadata_url_oidc(realm_url))


# ---------------------------------------------------------------------------
# DPoP
# ---------------------------------------------------------------------------


def _gen_ec_jwk() -> tuple[dict[str, str], dict[str, str]]:
    priv = ec.generate_private_key(ec.SECP256R1())
    pub = priv.public_key().public_numbers()
    d = priv.private_numbers().private_value
    private_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(pub.x.to_bytes(32, "big")),
        "y": _b64url(pub.y.to_bytes(32, "big")),
        "d": _b64url(d.to_bytes(32, "big")),
    }
    public_jwk = {k: private_jwk[k] for k in ("kty", "crv", "x", "y")}
    return private_jwk, public_jwk


def _dpop_proof(
    *,
    private_jwk: dict[str, str],
    public_jwk: dict[str, str],
    htm: str,
    htu: str,
    access_token: str | None = None,
    nonce: str | None = None,
) -> str:
    now = int(time.time())
    payload: dict[str, Any] = {
        "jti": secrets.token_urlsafe(16),
        "htm": htm.upper(),
        "htu": htu.split("?")[0],
        "iat": now,
    }
    if access_token:
        payload["ath"] = _b64url(hashlib.sha256(access_token.encode("ascii")).digest())
    if nonce:
        payload["nonce"] = nonce
    headers = {"typ": "dpop+jwt", "alg": "ES256", "jwk": public_jwk}
    return jwt.encode(
        payload,
        ECAlgorithm.from_jwk(json.dumps(private_jwk)),
        algorithm="ES256",
        headers=headers,
    )


def dpop_request(
    url: str,
    *,
    method: str,
    access_token: str,
    token_type: str,
    dpop_private: dict[str, str],
    dpop_public: dict[str, str],
    body: bytes | None = None,
    content_type: str | None = None,
    dpop_nonce: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Authenticated request with DPoP.

    If 401 + DPoP-Nonce, retry once with nonce in proof.
    Optional dpop_nonce seeds the first attempt.
    """
    # Ignore AS token_type casing/value — resource server requires "DPoP".
    _ = token_type
    auth_scheme = "DPoP"

    def once(nonce: str | None) -> tuple[int, dict[str, str], bytes]:
        dpop = _dpop_proof(
            private_jwk=dpop_private,
            public_jwk=dpop_public,
            htm=method,
            htu=url,
            access_token=access_token,
            nonce=nonce,
        )
        headers = {
            "Authorization": f"{auth_scheme} {access_token}",
            "DPoP": dpop,
        }
        if content_type:
            headers["Content-Type"] = content_type
        return _fetch(url, method=method, body=body, headers=headers, allow_redirects=False)

    status, headers, raw = once(dpop_nonce)
    if status == 401 and headers.get("dpop-nonce") and headers["dpop-nonce"] != dpop_nonce:
        status, headers, raw = once(headers["dpop-nonce"])
    return status, headers, raw


def _http_error_detail(status: int, headers: dict[str, str], raw: bytes, limit: int = 1200) -> str:
    """Include WWW-Authenticate / DPoP-Nonce so CI 401s are diagnosable."""
    auth = headers.get("www-authenticate") or ""
    nonce = headers.get("dpop-nonce") or ""
    extras = []
    if auth:
        extras.append(f"www-authenticate={auth!r}")
    if nonce:
        extras.append(f"dpop-nonce={nonce!r}")
    suffix = f" ({', '.join(extras)})" if extras else ""
    return f"HTTP {status}: {raw[:limit]!r}{suffix}"


# ---------------------------------------------------------------------------
# Token — authorization_code+PKCE (browser-shaped) vs password (headless local-dev)
# ---------------------------------------------------------------------------


def _pkce_pair() -> tuple[str, str]:
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


class _LoginFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.action: str | None = None
        self.inputs: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        ad = {k: (v or "") for k, v in attrs}
        if tag == "form" and self.action is None:
            self.action = ad.get("action") or None
        if tag == "input":
            name = ad.get("name")
            if name:
                self.inputs[name] = ad.get("value", "")


def obtain_access_token_authorization_code(
    *,
    auth_endpoint: str,
    token_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    username: str,
    password: str,
    dpop_private: dict[str, str],
    dpop_public: dict[str, str],
) -> dict[str, Any]:
    """Standard OAuth authorization_code + PKCE (+ DPoP on token request)."""
    code_verifier, code_challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)
    auth_url = (
        f"{auth_endpoint}?"
        + urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
        )
    )

    jar = http.cookiejar.CookieJar()

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
            return None

    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar), _NoRedirect)

    def open_no_redirect(
        url: str, data: bytes | None = None, headers: dict[str, str] | None = None
    ) -> tuple[int, str | None, bytes]:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method="POST" if data is not None else "GET")
        try:
            with opener.open(req, timeout=60) as resp:
                return resp.status, None, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers.get("Location"), exc.read() if hasattr(exc, "read") else b""

    status, location, body = open_no_redirect(auth_url)
    hops = 0
    while status in (301, 302, 303, 307, 308) and location and hops < 10:
        hops += 1
        if location.startswith(redirect_uri) or "code=" in location:
            code = (urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("code") or [None])[0]
            if code:
                break
            raise RuntimeError(f"callback without code: {location}")
        status, location, body = open_no_redirect(urllib.parse.urljoin(auth_url, location))
    else:
        code = None

    if not code:
        if status != 200:
            raise RuntimeError(f"expected login page, got HTTP {status}: {body[:400]!r}")
        parser = _LoginFormParser()
        parser.feed(body.decode("utf-8", errors="replace"))
        if not parser.action:
            raise RuntimeError("Keycloak login form action not found")
        form = dict(parser.inputs)
        form["username"] = username
        form["password"] = password
        action_url = urllib.parse.urljoin(auth_url, parser.action)
        status, location, body = open_no_redirect(
            action_url,
            data=urllib.parse.urlencode(form).encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        hops = 0
        while status in (301, 302, 303, 307, 308) and location and hops < 12:
            hops += 1
            if location.startswith(redirect_uri) or "code=" in location:
                code = (urllib.parse.parse_qs(urllib.parse.urlparse(location).query).get("code") or [None])[0]
                if code:
                    break
                raise RuntimeError(f"callback without code: {location}")
            status, location, body = open_no_redirect(urllib.parse.urljoin(action_url, location))
        else:
            code = None

    if not code:
        raise RuntimeError(
            f"failed to obtain authorization code for {username}: HTTP {status} loc={location!r} body={body[:500]!r}"
        )

    dpop = _dpop_proof(private_jwk=dpop_private, public_jwk=dpop_public, htm="POST", htu=token_endpoint)
    status, _headers, raw = _fetch(
        token_endpoint,
        method="POST",
        form={
            "grant_type": "authorization_code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code": code,
            "code_verifier": code_verifier,
        },
        headers={"DPoP": dpop},
        allow_redirects=False,
    )
    if status >= 400:
        raise RuntimeError(f"authorization_code token HTTP {status}: {raw[:800]!r}")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or not data.get("access_token"):
        raise RuntimeError(f"token response missing access_token: {data}")
    return data


def obtain_access_token_password_dpop(
    *,
    token_endpoint: str,
    client_id: str,
    username: str,
    password: str,
    scope: str,
    dpop_private: dict[str, str],
    dpop_public: dict[str, str],
) -> dict[str, Any]:
    """Local-dev headless token path: Resource Owner Password Credentials + DPoP."""
    dpop = _dpop_proof(private_jwk=dpop_private, public_jwk=dpop_public, htm="POST", htu=token_endpoint)
    status, _headers, raw = _fetch(
        token_endpoint,
        method="POST",
        form={
            "grant_type": "password",
            "client_id": client_id,
            "username": username,
            "password": password,
            "scope": scope,
        },
        headers={"DPoP": dpop},
        allow_redirects=False,
    )
    if status >= 400:
        raise RuntimeError(f"password token HTTP {status}: {raw[:800]!r}")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict) or not data.get("access_token"):
        raise RuntimeError(f"token response missing access_token: {data}")
    return data


def obtain_access_token(
    *,
    auth_endpoint: str,
    token_endpoint: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    username: str,
    password: str,
    dpop_private: dict[str, str],
    dpop_public: dict[str, str],
) -> dict[str, Any]:
    """Token acquisition used by issuance.

    Local-dev: prefer password+DPoP. Keycloak cookie/hostname binding often
    breaks urllib authorization_code against localhost NodePorts.
    Browser-shaped alternative: obtain_access_token_authorization_code(...).
    """
    try:
        return obtain_access_token_password_dpop(
            token_endpoint=token_endpoint,
            client_id=client_id,
            username=username,
            password=password,
            scope=scope,
            dpop_private=dpop_private,
            dpop_public=dpop_public,
        )
    except Exception as pwd_exc:  # noqa: BLE001
        try:
            return obtain_access_token_authorization_code(
                auth_endpoint=auth_endpoint,
                token_endpoint=token_endpoint,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                username=username,
                password=password,
                dpop_private=dpop_private,
                dpop_public=dpop_public,
            )
        except Exception as auth_exc:  # noqa: BLE001
            raise RuntimeError(
                f"password grant failed ({pwd_exc}); authorization_code failed ({auth_exc})"
            ) from auth_exc


# ---------------------------------------------------------------------------
# Credential proof — plain jwk header vs local-dev TS3 key_attestation
# ---------------------------------------------------------------------------


def build_proof_jwt_jwk_header(
    *,
    issuer_url: str,
    nonce: str,
    wallet_private_jwk: dict[str, Any],
    wallet_public_jwk: dict[str, Any],
) -> str:
    """OID4VCI proof JWT with public JWK in header (simpler / older style)."""
    jwk = {
        "kty": wallet_public_jwk["kty"],
        "crv": wallet_public_jwk["crv"],
        "x": wallet_public_jwk["x"],
        "y": wallet_public_jwk["y"],
    }
    payload = {"aud": issuer_url, "iat": int(time.time()), "nonce": nonce}
    headers = {"typ": "openid4vci-proof+jwt", "alg": "ES256", "jwk": jwk}
    return jwt.encode(
        payload,
        ECAlgorithm.from_jwk(json.dumps(wallet_private_jwk)),
        algorithm="ES256",
        headers=headers,
    )


def _self_signed_cert_der(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "DE"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "DCS testWallet"),
            x509.NameAttribute(NameOID.COMMON_NAME, "dev-wallet-provider"),
        ]
    )
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=4000))
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def build_key_attestation_jwt_local(
    *,
    attested_public_jwk: dict[str, Any],
    nonce: str | None = None,
    validity_days: int = 2000,
) -> str:
    """Local-dev: synthetic key-attestation+jwt for insecure/dev issuer."""
    wp_priv = ec.generate_private_key(ec.SECP256R1())
    wp_pub = wp_priv.public_key().public_numbers()
    wp_d = wp_priv.private_numbers().private_value
    wp_private_jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(wp_pub.x.to_bytes(32, "big")),
        "y": _b64url(wp_pub.y.to_bytes(32, "big")),
        "d": _b64url(wp_d.to_bytes(32, "big")),
    }
    now = int(time.time())
    exp = now + validity_days * 86400
    # Local-dev: placeholder status list (not a production attestation status).
    status = {
        "status_list": {
            "uri": "http://localhost:30822/token_status_list/dev/key-attestation",
            "idx": 0,
        }
    }
    claims: dict[str, Any] = {
        "iat": now,
        "exp": exp,
        "attested_keys": [
            {
                "kty": attested_public_jwk["kty"],
                "crv": attested_public_jwk["crv"],
                "x": attested_public_jwk["x"],
                "y": attested_public_jwk["y"],
            }
        ],
        "key_storage": ["iso_18045_high"],
        "user_authentication": ["iso_18045_high"],
        "certification": "https://localhost/dev-wallet-provider/certification",
        "status": status,
        "key_storage_status": {"status": status, "exp": exp},
    }
    if nonce:
        claims["nonce"] = nonce
    x5c_b64 = base64.b64encode(_self_signed_cert_der(wp_priv)).decode("ascii")
    headers = {"typ": "key-attestation+jwt", "alg": "ES256", "x5c": [x5c_b64]}
    return jwt.encode(
        claims,
        ECAlgorithm.from_jwk(json.dumps(wp_private_jwk)),
        algorithm="ES256",
        headers=headers,
    )


def build_proof_jwt(
    *,
    issuer_url: str,
    nonce: str,
    wallet_private_jwk: dict[str, Any],
    wallet_public_jwk: dict[str, Any],
) -> str:
    """Proof JWT used by issuance.

    Local-dev: eudi-srv-pid-issuer v0.10.x expects key_attestation (TS3) with
    kid=\"0\", not a plain jwk header. Simpler alternative: build_proof_jwt_jwk_header.
    """
    key_attestation = build_key_attestation_jwt_local(
        attested_public_jwk=wallet_public_jwk,
        nonce=nonce,
    )
    payload = {"aud": issuer_url, "iat": int(time.time()), "nonce": nonce}
    headers = {
        "typ": "openid4vci-proof+jwt",
        "alg": "ES256",
        "kid": "0",
        "key_attestation": key_attestation,
    }
    return jwt.encode(
        payload,
        ECAlgorithm.from_jwk(json.dumps(wallet_private_jwk)),
        algorithm="ES256",
        headers=headers,
    )


def _extract_credential_jwt(response: dict[str, Any]) -> str:
    if isinstance(response.get("credential"), str):
        return response["credential"].strip()
    credentials = response.get("credentials")
    if isinstance(credentials, list) and credentials:
        first = credentials[0]
        if isinstance(first, str):
            return first.strip()
        if isinstance(first, dict) and isinstance(first.get("credential"), str):
            return first["credential"].strip()
    raise RuntimeError(f"credential not found in response keys={list(response.keys())}: {response}")


def _decode_sdjwt_summary(sd_jwt: str) -> dict[str, Any]:
    issuer_jwt = sd_jwt.split("~", 1)[0]
    parts = issuer_jwt.split(".")
    if len(parts) < 2:
        return {"raw_prefix": sd_jwt[:80]}
    payload_b64 = parts[1] + "=" * ((4 - len(parts[1]) % 4) % 4)
    payload = json.loads(base64.urlsafe_b64decode(payload_b64))
    return {
        "iss": payload.get("iss"),
        "vct": payload.get("vct"),
        "exp": payload.get("exp"),
        "nbf": payload.get("nbf"),
        "status": payload.get("status"),
        "cnf": payload.get("cnf"),
        "disclosure_count": max(0, sd_jwt.count("~") - 1),
    }


# ---------------------------------------------------------------------------
# OID4VCI issuance orchestration
# ---------------------------------------------------------------------------


def issue_pid_for_user(
    *,
    username: str,
    password: str,
    issuer_url: str = DEFAULT_ISSUER,
    realm_url: str = DEFAULT_REALM,
    client_id: str = DEFAULT_CLIENT_ID,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    scope: str = DEFAULT_SCOPE,
    config_id: str = DEFAULT_CONFIG_ID,
    wallet_private_jwk: dict[str, Any],
    wallet_public_jwk: dict[str, Any],
) -> str:
    """Run OID4VCI issuance for one Keycloak holder; return SD-JWT string."""
    issuer_url = issuer_url.rstrip("/")
    realm_url = realm_url.rstrip("/")

    issuer_meta = discover_issuer_metadata(issuer_url)
    auth_meta = discover_as_metadata(realm_url=realm_url, issuer_meta=issuer_meta)

    auth_endpoint = str(auth_meta.get("authorization_endpoint") or "")
    token_endpoint = str(auth_meta.get("token_endpoint") or "")
    # Map advertised endpoints onto caller-reachable bases:
    # - auth/token → realm_url (host Traefik / NodePort, not dcs-keycloak)
    # - credential/nonce → issuer_url
    auth_endpoint = rewrite_endpoint_onto_base(realm_url, auth_endpoint)
    token_endpoint = rewrite_endpoint_onto_base(realm_url, token_endpoint)
    credential_endpoint = rewrite_endpoint_onto_base(
        issuer_url, str(issuer_meta.get("credential_endpoint") or "")
    )
    nonce_endpoint = rewrite_endpoint_onto_base(
        issuer_url, str(issuer_meta.get("nonce_endpoint") or "")
    )
    proof_aud = str(issuer_meta.get("credential_issuer") or issuer_url).rstrip("/")
    if not all([auth_endpoint, token_endpoint, credential_endpoint, nonce_endpoint]):
        raise RuntimeError("missing auth/token/credential/nonce endpoint")

    cfgs = issuer_meta.get("credential_configurations_supported") or {}
    cfg = cfgs.get(config_id)
    if not isinstance(cfg, dict):
        raise RuntimeError(f"issuer missing credential config {config_id!r}")
    fmt = str(cfg.get("format") or "")
    if not fmt:
        raise RuntimeError(f"config {config_id!r} missing format")

    dpop_private, dpop_public = _gen_ec_jwk()
    token_data = obtain_access_token(
        auth_endpoint=auth_endpoint,
        token_endpoint=token_endpoint,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=scope,
        username=username,
        password=password,
        dpop_private=dpop_private,
        dpop_public=dpop_public,
    )
    access_token = str(token_data["access_token"])
    token_type = str(token_data.get("token_type") or "DPoP")

    # Nonce endpoint is permitAll; sending Authorization+DPoP triggers DPoP auth
    # (issuer.dpop.nonce.enabled) and fails with 401 before the handler runs.
    status, nonce_headers, raw = _fetch(
        nonce_endpoint,
        method="POST",
        body=b"",
        headers={"Accept": "application/json"},
        allow_redirects=False,
    )
    if status >= 400:
        raise RuntimeError(f"nonce endpoint HTTP {status}: {raw[:800]!r}")
    nonce_data = json.loads(raw.decode("utf-8"))
    c_nonce = str(nonce_data.get("c_nonce") or "").strip()
    if not c_nonce:
        raise RuntimeError(f"nonce response missing c_nonce: {nonce_data}")
    dpop_nonce = (nonce_headers.get("dpop-nonce") or "").strip() or None

    proof_jwt = build_proof_jwt(
        issuer_url=proof_aud,
        nonce=c_nonce,
        wallet_private_jwk=wallet_private_jwk,
        wallet_public_jwk=wallet_public_jwk,
    )
    credential_request = {
        "credential_configuration_id": config_id,
        "format": fmt,
        "proofs": {"jwt": [proof_jwt]},
    }
    status, cred_headers, raw = dpop_request(
        credential_endpoint,
        method="POST",
        access_token=access_token,
        token_type=token_type,
        dpop_private=dpop_private,
        dpop_public=dpop_public,
        body=json.dumps(credential_request).encode("utf-8"),
        content_type="application/json",
        dpop_nonce=dpop_nonce,
    )
    if status >= 400:
        raise RuntimeError(
            f"credential endpoint {_http_error_detail(status, cred_headers, raw)}"
        )
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise RuntimeError(f"unexpected credential response: {data!r}")
    return _extract_credential_jwt(data)


def resolve_pid_usernames(credential_names: list[str] | None) -> list[str]:
    """Map request names to Keycloak PID holders (preserves PID_HOLDERS order)."""
    if credential_names is None:
        return list(PID_HOLDERS.keys())
    wanted = set(credential_names)
    return [u for u in PID_HOLDERS if u in wanted]


def holder_password(username: str, override: str | None = None) -> str:
    if override:
        return override
    configured = PID_HOLDERS.get(username)
    return configured if configured is not None else username


def issue_pid_credentials(
    *,
    credentials_dir: Path,
    wallet_private_jwk: dict,
    wallet_public_jwk: dict | None = None,
    credential_names: list[str] | None = None,
    issuer_url: str = DEFAULT_ISSUER,
    realm_url: str = DEFAULT_REALM,
    client_id: str = DEFAULT_CLIENT_ID,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
    password_override: str | None = None,
) -> list[Path]:
    """Issue ``<user>.pid.jwt`` for Keycloak PID holders (OID4VCI local stack).

    Local-dev: one shared wallet key for all holders when callers pass a
    single wallet_private_jwk (as issue_credentials.py does).
    """
    public_jwk = wallet_public_jwk or public_key_material(wallet_private_jwk)
    users = resolve_pid_usernames(credential_names)
    if not users:
        return []

    credentials_dir.mkdir(parents=True, exist_ok=True)
    output_paths: list[Path] = []
    for username in users:
        password = holder_password(username, password_override)
        sd_jwt = issue_pid_for_user(
            username=username,
            password=password,
            issuer_url=issuer_url,
            realm_url=realm_url,
            client_id=client_id,
            redirect_uri=redirect_uri,
            wallet_private_jwk=wallet_private_jwk,
            wallet_public_jwk=public_jwk,
        )
        out_path = credentials_dir / f"{username}.pid.jwt"
        out_path.write_text(sd_jwt + "\n", encoding="utf-8")
        output_paths.append(out_path)
    return output_paths


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Issue PID SD-JWTs via local OID4VCI (Keycloak holders → *.pid.jwt)"
    )
    parser.add_argument("--credentials-dir", type=Path, default=DEFAULT_CREDENTIALS_DIR)
    parser.add_argument(
        "--credential",
        action="append",
        dest="credentials",
        help="PID holder username (repeatable). Default: all PID_HOLDERS",
    )
    parser.add_argument("--issuer", default=DEFAULT_ISSUER)
    parser.add_argument("--realm", default=DEFAULT_REALM)
    parser.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    parser.add_argument("--redirect-uri", default=DEFAULT_REDIRECT_URI)
    parser.add_argument("--password", help="Override password for all selected users")
    parser.add_argument("--keys-dir", type=Path, default=WALLET_ROOT / "keys")
    args = parser.parse_args()


    wallet_private = private_key_material(load_json(args.keys_dir / "wallet.jwk"))
    wallet_public = public_key_material(wallet_private)

    if args.credentials:
        unknown = [n for n in args.credentials if n not in PID_HOLDERS]
        if unknown:
            raise SystemExit(f"not a Keycloak PID holder: {unknown}; known={sorted(PID_HOLDERS)}")

    paths = issue_pid_credentials(
        credentials_dir=args.credentials_dir,
        wallet_private_jwk=wallet_private,
        wallet_public_jwk=wallet_public,
        credential_names=args.credentials,
        issuer_url=args.issuer,
        realm_url=args.realm,
        client_id=args.client_id,
        redirect_uri=args.redirect_uri,
        password_override=args.password,
    )
    if not paths:
        print("no PID holders selected")
        return 0
    for path in paths:
        summary = _decode_sdjwt_summary(path.read_text(encoding="utf-8").strip())
        print(f"issued: {path} iss={summary.get('iss')} vct={summary.get('vct')} nbf={summary.get('nbf')}")
    print(f"issued {len(paths)} credential(s)")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 — CLI tool
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
