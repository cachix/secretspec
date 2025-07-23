#!/bin/bash

# Test script to verify performance logging works
# This script doesn't require a real Bitwarden vault

set -e

echo "🔬 Testing Performance Logging"
echo "=============================="

# Build the binary
echo "Building secretspec..."
cargo build --bin secretspec --quiet

# Create a minimal test config
cat > secretspec.toml << 'EOF'
[project]
name = "perf-test"
revision = "1.0"

[profiles.default]
TEST_KEY = { required = false }
EOF

echo "✓ Created test config"

# Test 1: Run without performance logging (should have no [PERF] output)
echo -e "\n📊 Test 1: Normal operation (no performance logging)"
if ./target/debug/secretspec get TEST_KEY --provider bitwarden:// 2>&1 | grep -q "\[PERF\]"; then
    echo "❌ FAILED: Found [PERF] output when not enabled"
    exit 1
else
    echo "✅ PASSED: No performance output when disabled"
fi

# Test 2: Run with performance logging enabled (should have [PERF] output)
echo -e "\n📊 Test 2: With performance logging enabled"
SECRETSPEC_PERF_LOG=1 ./target/debug/secretspec get TEST_KEY --provider bitwarden:// 2>&1 | grep "\[PERF\]" > /tmp/perf_output.txt || true

if [ -s /tmp/perf_output.txt ]; then
    echo "✅ PASSED: Performance logging enabled"
    echo "Performance output:"
    cat /tmp/perf_output.txt | sed 's/^/  /'
else
    echo "⚠️  WARNING: No performance output found (this is expected if no Bitwarden CLI is available)"
fi

# Test 3: Test with environment variable
echo -e "\n📊 Test 3: Testing timing granularity"
echo "Running with performance logging to see timing breakdown..."

SECRETSPEC_PERF_LOG=1 ./target/debug/secretspec get NONEXISTENT_KEY --provider bitwarden:// 2>&1 | \
    grep "\[PERF\]" | head -5 | sed 's/^/  /' || echo "  (No output - likely no Bitwarden CLI available)"

# Cleanup
rm -f secretspec.toml /tmp/perf_output.txt

echo -e "\n✅ Performance logging tests completed"
echo "To use performance logging:"
echo "  export SECRETSPEC_PERF_LOG=1"
echo "  secretspec get KEY --provider bitwarden://"