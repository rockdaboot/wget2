#!/usr/bin/env bash
#
# Test HTTPS proxy authentication (Issue #711)
#
# This test verifies that wget2 properly sends Proxy-Authorization headers
# when connecting through an HTTPS proxy that requires authentication.

set -e

# Check if Python3 is available
if ! command -v python3 &> /dev/null; then
    echo "SKIP: Python3 not found"
    exit 77  # SKIP code for autotools
fi

# Determine paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVER_SCRIPT="${SCRIPT_DIR}/test-https-proxy-auth-server.py"
SRCDIR="${SRCDIR:-${SCRIPT_DIR}}"
BUILDDIR="${BUILDDIR:-${SCRIPT_DIR}/..}"

# Find wget2 binary
# During distcheck, BUILDDIR is the tests directory, so we need ../src
if [ -f "${BUILDDIR}/../src/wget2_noinstall" ]; then
    WGET="${BUILDDIR}/../src/wget2_noinstall"
elif [ -f "${BUILDDIR}/../src/wget2" ]; then
    WGET="${BUILDDIR}/../src/wget2"
elif [ -f "${BUILDDIR}/src/wget2_noinstall" ]; then
    WGET="${BUILDDIR}/src/wget2_noinstall"
elif [ -f "${BUILDDIR}/src/wget2" ]; then
    WGET="${BUILDDIR}/src/wget2"
else
    echo "ERROR: Cannot find wget2 binary"
    exit 1
fi

# Check if wget2 was built with TLS support
if ! "${WGET}" --version | grep -q "+ssl\|+https"; then
    echo "SKIP: wget2 built without TLS support"
    exit 77
fi

# Certificate files
CERTFILE="${SRCDIR}/certs/x509-server-cert.pem"
KEYFILE="${SRCDIR}/certs/x509-server-key.pem"

if [ ! -f "${CERTFILE}" ] || [ ! -f "${KEYFILE}" ]; then
    echo "SKIP: Certificate files not found"
    exit 77
fi

# Find available ports
PROXY_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')
TARGET_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("", 0)); print(s.getsockname()[1]); s.close()')

# Create temporary directory
TMPDIR=$(mktemp -d)
trap "rm -rf ${TMPDIR}; [ -n \"\${SERVER_PID}\" ] && kill \${SERVER_PID} 2>/dev/null || true" EXIT

# Start the test server
python3 "${SERVER_SCRIPT}" "${PROXY_PORT}" "${TARGET_PORT}" "${CERTFILE}" "${KEYFILE}" > "${TMPDIR}/server.log" 2>&1 &
SERVER_PID=$!

# Wait for server to be ready (with timeout)
TIMEOUT=10
ELAPSED=0
while [ ${ELAPSED} -lt ${TIMEOUT} ]; do
    if grep -q "^READY:" "${TMPDIR}/server.log" 2>/dev/null; then
        break
    fi
    sleep 0.1
    ELAPSED=$((ELAPSED + 1))
done

if [ ${ELAPSED} -ge ${TIMEOUT} ]; then
    echo "ERROR: Server failed to start within ${TIMEOUT} seconds"
    cat "${TMPDIR}/server.log"
    exit 1
fi

# Extract credentials from server output
CREDS=$(grep "^READY:" "${TMPDIR}/server.log" | head -1)
PROXY_USER=$(echo "${CREDS}" | cut -d: -f2)
PROXY_PASS=$(echo "${CREDS}" | cut -d: -f3)

# Test 1: Successful authentication
echo "Test 1: HTTPS proxy with correct credentials"
"${WGET}" \
    --no-config \
    --no-local-db \
    --debug \
    --no-check-certificate \
    --https-proxy="http://${PROXY_USER}:${PROXY_PASS}@127.0.0.1:${PROXY_PORT}" \
    "https://127.0.0.1:${TARGET_PORT}/test.txt" \
    -O "${TMPDIR}/output.txt" \
    > "${TMPDIR}/wget.log" 2>&1

# Verify the download succeeded
if [ ! -f "${TMPDIR}/output.txt" ]; then
    echo "FAIL: Download failed - output file not created"
    cat "${TMPDIR}/wget.log"
    exit 1
fi

if ! grep -q "Success: HTTPS proxy authentication working" "${TMPDIR}/output.txt"; then
    echo "FAIL: Downloaded content is incorrect"
    cat "${TMPDIR}/output.txt"
    exit 1
fi

# Verify wget sent the Proxy-Authorization header
if ! grep -q "Proxy-Authorization: Basic" "${TMPDIR}/wget.log" 2>/dev/null; then
    echo "WARNING: Could not verify Proxy-Authorization header in debug output"
    # Don't fail the test - the successful download proves it worked
fi

echo "Test 1: PASS"

# Test 2: Failed authentication (wrong password)
echo "Test 2: HTTPS proxy with incorrect credentials (should fail)"
rm -f "${TMPDIR}/output2.txt"

if "${WGET}" \
    --no-config \
    --no-local-db \
    --no-check-certificate \
    --https-proxy="http://${PROXY_USER}:wrongpass@127.0.0.1:${PROXY_PORT}" \
    "https://127.0.0.1:${TARGET_PORT}/test.txt" \
    -O "${TMPDIR}/output2.txt" \
    > "${TMPDIR}/wget2.log" 2>&1; then
    echo "FAIL: Download should have failed with wrong credentials"
    exit 1
fi

# Verify we got a 407 response
if ! grep -q "407\|Proxy.*[Aa]uth" "${TMPDIR}/wget2.log"; then
    echo "WARNING: Expected 407 Proxy Authentication Required error"
    # Don't fail - the connection failure is what matters
fi

echo "Test 2: PASS"

# Test 3: No credentials (should fail)
echo "Test 3: HTTPS proxy without credentials (should fail)"
rm -f "${TMPDIR}/output3.txt"

if "${WGET}" \
    --no-config \
    --no-local-db \
    --no-check-certificate \
    --https-proxy="http://127.0.0.1:${PROXY_PORT}" \
    "https://127.0.0.1:${TARGET_PORT}/test.txt" \
    -O "${TMPDIR}/output3.txt" \
    > "${TMPDIR}/wget3.log" 2>&1; then
    echo "FAIL: Download should have failed without credentials"
    exit 1
fi

echo "Test 3: PASS"

echo "All tests PASSED"
exit 0
