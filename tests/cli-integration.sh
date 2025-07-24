#!/bin/bash
set -euo pipefail

echo "Running CLI integration tests..."

# Use dotenv provider for testing
export SECRETSPEC_PROVIDER=dotenv
# Ensure we use the default profile for tests
export SECRETSPEC_PROFILE=default

# Test directory for isolated tests
TEST_DIR="$(mktemp -d)"
cd "$TEST_DIR"

# Helper function to check command success
check_success() {
    if [ $? -eq 0 ]; then
        echo "✓ $1"
    else
        echo "✗ $1"
        exit 1
    fi
}

# Helper function to check command failure
check_failure() {
    if [ $? -ne 0 ]; then
        echo "✓ $1"
    else
        echo "✗ $1"
        exit 1
    fi
}

# Test 1: Help command
secretspec --help > /dev/null
check_success "Help command works"

# Test 2: Version command
secretspec --version > /dev/null
check_success "Version command works"

# Test 3: Init command
secretspec init
check_success "Init command creates secretspec.toml"

# Verify the file was created
[ -f "secretspec.toml" ]
check_success "secretspec.toml file exists"

# Test 4: Declare and set a secret
cat > secretspec.toml << EOF
[project]
name = "test-app"
revision = "1.0"

[profiles.default]
TEST_SECRET = { description = "Test secret for integration tests" }
EOF

echo "test_value" | secretspec set TEST_SECRET
check_success "Set TEST_SECRET"

# Get the secret
VALUE=$(secretspec get TEST_SECRET)
[ "$VALUE" = "test_value" ]
check_success "Get TEST_SECRET returns correct value"

# Test 5: Check command with missing required secret
cat > secretspec.toml << EOF
[project]
name = "test-app"
revision = "1.0"

[profiles.default]
TEST_SECRET = { description = "Test secret for integration tests" }
REQUIRED_SECRET = { description = "Required secret", required = true }
EOF

# Test that check fails when required secret is missing
if secretspec check 2>/dev/null; then
    # Should have failed but didn't
    echo "✗ Check fails with missing required secret"
    exit 1
else
    echo "✓ Check fails with missing required secret"
fi

# Set the required secret
echo "required_value" | secretspec set REQUIRED_SECRET
check_success "Set REQUIRED_SECRET"

# Now check should pass
secretspec check
check_success "Check passes with all required secrets"

# Test 6: Import from .env file
cat > .env.import << EOF
ENV_VAR1=value1
ENV_VAR2=value2
EOF

# First declare the secrets we're importing
cat > secretspec.toml << EOF
[project]
name = "test-app"
revision = "1.0"

[profiles.default]
TEST_SECRET = { description = "Test secret" }
REQUIRED_SECRET = { description = "Required secret", required = true }
ENV_VAR1 = { description = "Imported from .env" }
ENV_VAR2 = { description = "Imported from .env" }
EOF

secretspec import dotenv://.env.import
check_success "Import from .env file"

# Verify imported values
VALUE1=$(secretspec get ENV_VAR1)
VALUE2=$(secretspec get ENV_VAR2)
[ "$VALUE1" = "value1" ] && [ "$VALUE2" = "value2" ]
check_success "Imported values are correct"

# Test 7: Run command with secrets
echo "#!/usr/bin/env bash" > test_script.sh
echo "echo \"\$TEST_SECRET\"" >> test_script.sh
chmod +x test_script.sh

OUTPUT=$(secretspec run -- ./test_script.sh)
[ "$OUTPUT" = "test_value" ]
check_success "Run command with secrets injected"

# Test 8: Profile support - init doesn't need profile, just add the profile to config

# Declare secret in production profile
cat >> secretspec.toml << EOF

[profiles.production]
PROD_SECRET = { description = "Production secret" }
EOF

echo "prod_value" | secretspec set --profile production PROD_SECRET
check_success "Set secret in production profile"

# Test 9: List secrets - removed as this command doesn't exist

# Test 10: Config command
secretspec config show > /dev/null
check_success "Config show command works"

# Test 11: Init from provider
# Create a .env file to import from
cat > .env.source << EOF
API_KEY=test-api-key
DATABASE_URL=postgres://localhost/test
EOF

# Test init with bare provider name
rm -f secretspec.toml
secretspec init --from dotenv:.env.source
check_success "Init from dotenv provider with path"

# Verify secrets were imported
grep -q "API_KEY" secretspec.toml && grep -q "DATABASE_URL" secretspec.toml
check_success "Init imported secrets from .env file"

# Test init with bare provider name (should use default .env)
echo "DEFAULT_KEY=default-value" > .env
rm -f secretspec.toml
secretspec init --from dotenv
check_success "Init from dotenv provider (bare name)"

# Verify it found the default .env
grep -q "DEFAULT_KEY" secretspec.toml
check_success "Init found default .env file"

# Test 12: Default value handling
cat > secretspec.toml << EOF
[project]
name = "test-app"
revision = "1.0"

[profiles.default]
DEFAULT_SECRET = { description = "Secret with default", default = "default_value" }
EOF

# Should use default value when not set
VALUE=$(secretspec get DEFAULT_SECRET)
[ "$VALUE" = "default_value" ]
check_success "Default value is used when secret not set"

# Cleanup
cd ..
rm -rf "$TEST_DIR"

echo "All CLI integration tests passed!"
