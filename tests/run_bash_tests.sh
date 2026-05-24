#!/usr/bin/env bash
# Smoke test for credhunter.sh — runs against tests/fixtures/linux/ and asserts findings
set -u
cd "$(dirname "$0")/.."
rm -rf credhunter-loot-* 2>/dev/null

out=$(./credhunter.sh --output console --no-color --skip-known-locations tests/fixtures/linux 2>&1)
echo "----- captured output -----"
echo "$out"
echo "----- end output -----"

fail=0
assert() {
  if ! grep -q "$1" <<<"$out"; then
    echo "FAIL: expected finding not present: $1"
    fail=1
  else
    echo "PASS: $1"
  fi
}
refute() {
  if grep -q "$1" <<<"$out"; then
    echo "FAIL: unexpected finding present: $1"
    fail=1
  else
    echo "PASS (negative): $1"
  fi
}

# Expected HIGH findings
assert "shadow.hash"
assert "pem.private_key"
assert "mycnf.password"
assert "uri.basic_creds"
assert "gpp.cpassword"
assert "netrc"
assert "dotnet.connstr"
# Refute: should not chase the API token (out of scope)
refute "AKIAIOSFODNN7EXAMPLE"

if [[ "$fail" -eq 0 ]]; then
  echo "ALL TESTS PASSED"
  exit 0
else
  echo "SOME TESTS FAILED"
  exit 1
fi
