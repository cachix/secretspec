#!/bin/bash

# SecretSpec Bitwarden Integration Test Script
# Tests the Bitwarden provider against actual vault data
# Usage: ./bitwarden_integration.sh [BW_SESSION]
#
# SETUP REQUIREMENTS:
# ===================
# This script requires specific test data to be set up in your Bitwarden vault.
# Create a folder named 'secretspec-test' and add the following items:
#
# BITWARDEN PASSWORD MANAGER ITEMS (in 'secretspec-test' folder):
# ----------------------------------------------------------------
# 1. Login Item: "Test Database"
#    - Username: testuser
#    - Password: tets-db-password
#    - Custom field: api_key = sk_test_db_12345
#
# 2. Login Item: "GitHub API"
#    - Username: (any)
#    - Password: (any fake GitHub token value)
#
# 3. Credit Card Item: "Stripe Test Card"
#    - Card Number: 4242424242424242
#    - Custom field: api_key = sk_test_stripe_12345
#
# 4. Credit Card Item: "Payment Gateway"
#    - Card Number: 5555555555554444
#    - (Used for default field testing)
#
# 5. SSH Key Item: "Deploy SSH Key"
#    - Private Key: (any SSH private key starting with "BEGIN OPENSSH PRIVATE KEY")
#    - Custom field: passphrase = ssh_passphrase_123
#
# 6. Identity Item: "Employee Record"
#    - Email: test.employee@example.com
#    - Custom field: employee_id = EMP001
#
# 7. Secure Note Item: "Note to Self"
#    - Note contents: this is a note.
#
# BWS (BITWARDEN SECRETS MANAGER) SETUP:
# ---------------------------------------
# If testing BWS functionality, create these secrets in your BWS project:
# - TEST_BWS_SECRET with value: bws_secret_value_123
# - API_TOKEN with value: bws_api_token_456
# - DATABASE_URL with value: (any database URL)
#
# Set BWS_ACCESS_TOKEN environment variable with your BWS access token.
#
# AUTHENTICATION:
# ---------------
# 1. Install Bitwarden CLI: npm install -g @bitwarden/cli
# 2. Login: bw login
# 3. Unlock vault: bw unlock
# 4. Pass the session key to this script or set BW_SESSION environment variable

set -e  # Exit on any error

# Get BW_SESSION from command line or environment
if [ $# -gt 0 ]; then
    BW_SESSION="$1"
    echo "Using BW_SESSION from command line argument"
elif [ -n "$BW_SESSION" ]; then
    echo "Using BW_SESSION from environment variable"
else
    echo "ERROR: BW_SESSION is required either as argument or environment variable"
    echo "Usage: $0 [BW_SESSION]"
    echo "Or: BW_SESSION=your_session $0"
    exit 1
fi

echo "🔐 SecretSpec Bitwarden Real-World Testing"
echo "=========================================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test counter
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run a test
run_test() {
    local test_name="$1"
    local command="$2"
    local expected_pattern="$3"

    # Prepend BW_SESSION to the command if it's a secretspec command
    if [[ "$command" == *"secretspec"* ]] && [[ "$command" != *"BW_SESSION"* ]]; then
        command="BW_SESSION='$BW_SESSION' $command"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "\n${BLUE}Test $TESTS_RUN: $test_name${NC}"
    echo "Command: $command"

    if output=$(eval "$command" 2>&1); then
        if [[ -z "$expected_pattern" ]] || echo "$output" | grep -q "$expected_pattern"; then
            echo -e "${GREEN}✓ PASSED${NC}: $output"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "${RED}✗ FAILED${NC}: Expected pattern '$expected_pattern' not found in output: $output"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    else
        echo -e "${RED}✗ FAILED${NC}: Command failed with error: $output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    fi
}

# Function to run a test expecting failure
run_test_expect_fail() {
    local test_name="$1"
    local command="$2"
    local expected_error_pattern="$3"

    # Prepend BW_SESSION to the command if it's a secretspec command
    if [[ "$command" == *"secretspec"* ]] && [[ "$command" != *"BW_SESSION"* ]]; then
        command="BW_SESSION='$BW_SESSION' $command"
    fi

    TESTS_RUN=$((TESTS_RUN + 1))
    echo -e "\n${BLUE}Test $TESTS_RUN: $test_name${NC}"
    echo "Command: $command (expecting failure)"

    if output=$(eval "$command" 2>&1); then
        echo -e "${RED}✗ FAILED${NC}: Expected command to fail, but it succeeded: $output"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        if [[ -z "$expected_error_pattern" ]] || echo "$output" | grep -q "$expected_error_pattern"; then
            echo -e "${GREEN}✓ PASSED${NC}: Got expected error: $output"
            TESTS_PASSED=$((TESTS_PASSED + 1))
        else
            echo -e "${RED}✗ FAILED${NC}: Expected error pattern '$expected_error_pattern' not found in: $output"
            TESTS_FAILED=$((TESTS_FAILED + 1))
        fi
    fi
}

echo -e "\n${YELLOW}Prerequisites Check${NC}"
echo "Checking Bitwarden CLI authentication..."

# Check BW authentication
if ! BW_SESSION="$BW_SESSION" bw status | grep -q "unlocked"; then
    echo -e "${RED}ERROR: Bitwarden vault is not unlocked with provided session!${NC}"
    echo "Please run: bw unlock"
    echo "Then pass the session as argument: $0 'your_session_here'"
    echo "Provided session starts with: ${BW_SESSION:0:20}..."
    exit 1
fi

echo -e "${GREEN}✓ Bitwarden CLI is authenticated and unlocked${NC}"

# Check if BWS is available and authenticated
if command -v bws &> /dev/null && [ -n "$BWS_ACCESS_TOKEN" ]; then
    echo -e "${GREEN}✓ BWS CLI is available with access token${NC}"
    BWS_AVAILABLE=true
else
    echo -e "${YELLOW}⚠ BWS CLI or BWS_ACCESS_TOKEN not available - skipping BWS tests${NC}"
    BWS_AVAILABLE=false
fi

# Create a test secretspec.toml
echo -e "\n${YELLOW}Setting up test configuration${NC}"
cat > secretspec.toml << 'EOF'
[project]
name = "bitwarden-test"
revision = "1.0"

[profiles.default]
# Keys that match EXACT Bitwarden item names for search
"Test Database" = { required = true, description = "Password from Test Database login item" }
"GitHub API" = { required = true, description = "Token from GitHub API item" }
"Stripe Test Card" = { required = true, description = "API key from Stripe Test Card item" }
"Deploy SSH Key" = { required = true, description = "SSH key from Deploy SSH Key item" }
"Employee Record" = { required = true, description = "Employee data from Employee Record identity item" }
"Note to Self" = { required = true, description = "Note contents from Note to Self secure note" }
"Payment Gateway" = { required = true, description = "Payment Gateway card item" }
"test" = { required = true, description = "Test item for fallback behavior" }

# Additional test secrets (optional)
NONEXISTENT_KEY = { required = false, description = "Key that should not exist" }
DEFINITELY_NONEXISTENT_ITEM = { required = false, description = "Item that definitely should not exist" }
CARD_NUMBER = { required = false, description = "Card number field" }
NEW_LOGIN_SECRET = { required = false, description = "New login secret for creation test" }
NEW_CARD_TOKEN = { required = false, description = "New card token for creation test" }
DATABASE_PASSWORD = { required = false, description = "Database password for update test" }

# BWS secrets (optional) - using actual BWS key names
TEST_BWS_SECRET = { required = false, description = "Test secret from BWS" }
API_TOKEN = { required = false, description = "API token from BWS" }
DATABASE_URL = { required = false, description = "Database URL from BWS" }
EOF

echo -e "${GREEN}✓ Created test secretspec.toml${NC}"

# Build the binary first to avoid warnings during tests
echo -e "\n${YELLOW}Building secretspec binary...${NC}"
cargo build --bin secretspec --quiet
echo -e "${GREEN}✓ Binary built successfully${NC}"

echo -e "\n${YELLOW}=== PASSWORD MANAGER TESTS ===${NC}"

# Test 1: Login Items - Default password field (Test Database)
run_test "Get password from Login item (default field)" \
    "./target/debug/secretspec get 'Test Database' --provider 'bitwarden://?type=login'" \
    "tets-db-password"

# Test 2: Login Items - Custom field (Test Database api_key)
run_test "Get custom field from Login item" \
    "./target/debug/secretspec get 'Test Database' --provider 'bitwarden://?type=login&field=api_key'" \
    "sk_test_db_12345"

# Test 3: Login Items - Username field (Test Database)
run_test "Get username from Login item" \
    "./target/debug/secretspec get 'Test Database' --provider 'bitwarden://?type=login&field=username'" \
    "testuser"

# Test 4: Credit Card Items - Custom field (Stripe Test Card)
run_test "Get API key from Credit Card item" \
    "./target/debug/secretspec get 'Stripe Test Card' --provider 'bitwarden://?type=card&field=api_key'" \
    "sk_test_stripe_12345"

# Test 5: Credit Card Items - Standard field
run_test "Get card number from Credit Card item" \
    "./target/debug/secretspec get 'Stripe Test Card' --provider 'bitwarden://?type=card&field=number'" \
    "4242424242424242"

# Test 6: Identity Items - Custom field (field required)
run_test "Get employee ID from Identity item" \
    "./target/debug/secretspec get 'Employee Record' --provider 'bitwarden://?type=identity&field=employee_id'" \
    "EMP001"

# Test 7: Identity Items - Standard field
run_test "Get email from Identity item" \
    "./target/debug/secretspec get 'Employee Record' --provider 'bitwarden://?type=identity&field=email'" \
    "test.employee@example.com"

# Test 8: SSH Key Items - Default field (private key)
run_test "Get private key from SSH Key item (default field)" \
    "./target/debug/secretspec get 'Deploy SSH Key' --provider 'bitwarden://?type=sshkey'" \
    "BEGIN OPENSSH PRIVATE KEY"

# Test 9: SSH Key Items - Custom field
run_test "Get passphrase from SSH Key item" \
    "./target/debug/secretspec get 'Deploy SSH Key' --provider 'bitwarden://?type=sshkey&field=passphrase'" \
    "ssh_passphrase_123"

# Test 10: Secure Note Items - Get note contents
run_test "Get value from Secure Note item" \
    "./target/debug/secretspec get 'Note to Self' --provider 'bitwarden://?type=securenote'" \
    "this is a note."

echo -e "\n${YELLOW}=== ENVIRONMENT VARIABLE TESTS ===${NC}"

# Test 11: Environment variable for type
run_test "Get API key using environment variable type" \
    "BITWARDEN_DEFAULT_TYPE=card BITWARDEN_DEFAULT_FIELD=api_key ./target/debug/secretspec get 'Stripe Test Card' --provider bitwarden://" \
    "sk_test_stripe_12345"

# Test 12: Environment variable for field
run_test "Get username using environment variable field" \
    "BITWARDEN_DEFAULT_TYPE=login BITWARDEN_DEFAULT_FIELD=username ./target/debug/secretspec get 'Test Database' --provider bitwarden://" \
    "testuser"

# Test 13: One-liner with multiple environment variables
run_test "Get employee ID with environment variables" \
    "BITWARDEN_DEFAULT_TYPE=identity BITWARDEN_DEFAULT_FIELD=employee_id ./target/debug/secretspec get 'Employee Record' --provider bitwarden://" \
    "EMP001"

echo -e "\n${YELLOW}=== ERROR HANDLING TESTS ===${NC}"

# Test 14: Missing field specification for Card items
run_test "Card item without field specification returns default field" \
    "./target/debug/secretspec get 'Payment Gateway' --provider 'bitwarden://?type=card'" \
    "5555555555554444"

# Test 15: Invalid item type should fail
run_test_expect_fail "Invalid item type should fail" \
    "./target/debug/secretspec get 'DEFINITELY_NONEXISTENT_ITEM' --provider 'bitwarden://?type=invalid'" \
    "not found"

# Test 16: Non-existent item
run_test_expect_fail "Non-existent item should return error or empty" \
    "./target/debug/secretspec get NONEXISTENT_KEY --provider 'bitwarden://?type=login'" \
    ""

echo -e "\n${YELLOW}=== ITEM CREATION TESTS ===${NC}"

# Sync vault before creation tests to avoid cipher conflicts
echo "Syncing Bitwarden vault..."
if ! BW_SESSION="$BW_SESSION" bw sync; then
    echo -e "${YELLOW}Warning: Vault sync failed, creation tests may fail${NC}"
fi

# Test 20: Create new Login item
run_test "Create new Login item" \
    "./target/debug/secretspec set NEW_LOGIN_SECRET 'test-new-secret' --provider 'bitwarden://?type=login'" \
    "Secret.*saved"

# Test 21: Create new Card item with custom field
run_test "Create new Card item with custom field" \
    "./target/debug/secretspec set NEW_CARD_TOKEN 'test-card-token' --provider 'bitwarden://?type=card&field=api_token'" \
    "Secret.*saved"

# Test 22: Update existing item
run_test "Update existing Login item" \
    "./target/debug/secretspec set DATABASE_PASSWORD 'updated-password' --provider 'bitwarden://?type=login'" \
    "Secret.*saved"

# BWS Tests (if available)
if [ "$BWS_AVAILABLE" = true ]; then
    echo -e "\n${YELLOW}=== BWS (SECRETS MANAGER) TESTS ===${NC}"

    # Test 23: Get secret from BWS
    run_test "Get secret from BWS" \
        "./target/debug/secretspec get TEST_BWS_SECRET --provider bws://" \
        "bws_secret_value_123"

    # Test 24: Get API token from BWS
    run_test "Get API token from BWS" \
        "./target/debug/secretspec get API_TOKEN --provider bws://" \
        "bws_api_token_456"
fi

echo -e "\n${YELLOW}=== TEST SUMMARY ===${NC}"
echo "=========================================="
echo "Tests Run:    $TESTS_RUN"
echo -e "Tests Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests Failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 ALL TESTS PASSED!${NC}"
    echo "The Bitwarden provider is working correctly with real vault data."
else
    echo -e "\n${RED}❌ SOME TESTS FAILED${NC}"
    echo "Please review the failed tests above."
fi

# Cleanup
echo -e "\n${YELLOW}Cleaning up test files...${NC}"
rm -f secretspec.toml

echo -e "\n${BLUE}Testing complete!${NC}"
