#!/bin/sh
# Generates the throwaway RSA key pair and mints the signed-cookie fixture used
# by the Go integration test. Run from the repository root.
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
FIXTURE_DIR="$SCRIPT_DIR/../../data/tests"

mkdir -p "$FIXTURE_DIR"

# Throwaway key pair. The public key is registered as a trusted signer by the
# Go test; the private key is used only to mint the cookie fixture.
openssl genrsa -out "$FIXTURE_DIR/test_private.pem" 2048
openssl rsa -in "$FIXTURE_DIR/test_private.pem" -outform PEM -pubout -out "$FIXTURE_DIR/test_public.pem"

# Mint a cookie with a far-future expiry (year 2100).
(
  cd "$SCRIPT_DIR"
  pnpm install --frozen-lockfile
  pnpm sign \
    "$FIXTURE_DIR/test_private.pem" \
    APKA1234 \
    "https://cdn.example.com/i/*" \
    --epoch 4102444800 \
    > "$FIXTURE_DIR/cookies.json"
)

echo "generated $FIXTURE_DIR/test_private.pem"
echo "generated $FIXTURE_DIR/test_public.pem"
echo "generated $FIXTURE_DIR/cookies.json"
