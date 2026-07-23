#!/usr/bin/env bash
# Issue EUDI PID SD-JWTs against the live kind stack for Playwright signing.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
VENV_PYTHON="${E2E_BDD_PYTHON:-${VENV_PATH:-$HOME/.dcs-bdd-venv}/bin/python3}"
OUT_DIR="${E2E_PID_CREDENTIALS_DIR:-$PROJECT_ROOT/tests/bdd/.tmp/e2e-pid-credentials}"
ENV_FILE="${E2E_PID_ENV_FILE:-$PROJECT_ROOT/tests/bdd/.tmp/e2e-pid.env}"
ISSUER_URL="${E2E_PID_ISSUER_URL:-${BDD_PUBLIC_ORIGIN:-http://localhost:18080}/pid-issuer}"
REALM_URL="${E2E_PID_REALM_URL:-${BDD_PUBLIC_ORIGIN:-http://localhost:18080}/realms/gaia-x}"

mkdir -p "$OUT_DIR" "$(dirname "$ENV_FILE")"

echo "Waiting for EUDI pid-issuer at $ISSUER_URL ..."
deadline=$(( $(date +%s) + 300 ))
until curl -sf "$ISSUER_URL/.well-known/openid-credential-issuer" >/dev/null 2>&1; do
  if [ "$(date +%s)" -gt "$deadline" ]; then
    echo "timed out waiting for pid-issuer discovery at $ISSUER_URL" >&2
    exit 1
  fi
  sleep 3
done

echo "Issuing EUDI PIDs for e2e (johndoe, janesmith) into $OUT_DIR"
"$VENV_PYTHON" "$PROJECT_ROOT/testWallet/scripts/issue_pid_credentials.py" \
  --credentials-dir "$OUT_DIR" \
  --credential johndoe \
  --credential janesmith \
  --issuer "$ISSUER_URL" \
  --realm "$REALM_URL"

# Issuer nbf ≈ iat+20s — give presentations a safe margin before Playwright starts.
sleep 25

cat > "$ENV_FILE" <<EOF
E2E_PID_JWT_A=$OUT_DIR/johndoe.pid.jwt
E2E_PID_JWT_B=$OUT_DIR/janesmith.pid.jwt
EOF
echo "Wrote $ENV_FILE"
cat "$ENV_FILE"
