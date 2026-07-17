#!/bin/bash

# SecretSpec Bitwarden Integration Test Script
# Tests the Bitwarden provider against actual vault data
# Usage: ./bitwarden_integration.sh [BW_SESSION]
#
# The script auto-creates test items if they don't exist,
# and removes them on clean exit (unless --keep-test-data is passed).
#
set -e  # Exit on any error

# Get BW_SESSION from command line or environment
KEEP_TEST_DATA=false
if [ $# -gt 0 ]; then
    if [ "$1" = "--keep-test-data" ]; then
        KEEP_TEST_DATA=true
        shift
    fi
    if [ $# -gt 0 ]; then
        BW_SESSION="$1"
    fi
fi
if [ -z "$BW_SESSION" ]; then
    echo "ERROR: BW_SESSION is required either as argument or environment variable"
    echo "Usage: $0 [--keep-test-data] [BW_SESSION]"
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

# Items created by this script (for cleanup)
CREATED_ITEM_IDS=()

# Ensure a BW item exists with the given JSON template. If it already
# exists, returns its ID. Otherwise creates it and records the ID.
ensure_item() {
    local name="$1"
    local template_json="$2"

    # Check if item already exists
    local existing_id
    existing_id=$(BW_SESSION="$BW_SESSION" bw list items --search "$name" 2>/dev/null | \
        python3 -c "import sys,json; items=[i for i in json.load(sys.stdin) if i.get('name','')=='$name']; print(items[0]['id'] if items else '')" 2>/dev/null || true)

    if [ -n "$existing_id" ]; then
        echo "   Using existing item: $name ($existing_id)"
        echo "$existing_id"
        return
    fi

    # Create the item via base64-encoded JSON
    local encoded
    encoded=$(echo -n "$template_json" | python3 -c "import sys,base64; sys.stdout.write(base64.b64encode(sys.stdin.buffer.read()).decode())")
    local new_id
    new_id=$(echo "$encoded" | BW_SESSION="$BW_SESSION" bw create item 2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || true)

    if [ -n "$new_id" ]; then
        echo "   Created item: $name ($new_id)"
        CREATED_ITEM_IDS+=("$new_id")
        echo "$new_id"
    else
        echo "   WARNING: Failed to create item: $name" >&2
    fi
}

# Set up test data automatically
setup_test_data() {
    echo -e "\n${YELLOW}Setting up test data...${NC}"

    # 1. Login Item: "Test Database"
    ensure_item "Test Database" '{"type":1,"name":"Test Database","login":{"username":"testuser","password":"tets-db-password","totp":null,"uris":[]},"fields":[{"name":"api_key","value":"sk_test_db_12345","type":1}],"notes":"SecretSpec test item"}' > /dev/null

    # 2. Login Item: "GitHub API"
    ensure_item "GitHub API" '{"type":1,"name":"GitHub API","login":{"username":"testuser","password":"ghp_fake_token_for_testing","totp":null,"uris":[]},"notes":"SecretSpec test item"}' > /dev/null

    # 3. Card Item: "Stripe Test Card"
    ensure_item "Stripe Test Card" '{"type":3,"name":"Stripe Test Card","card":{"cardholderName":"Test User","number":"4242424242424242","brand":"Visa","expMonth":"12","expYear":"2030","code":"123"},"fields":[{"name":"api_key","value":"sk_test_stripe_12345","type":1}],"notes":"SecretSpec test item"}' > /dev/null

    # 4. Card Item: "Payment Gateway"
    ensure_item "Payment Gateway" '{"type":3,"name":"Payment Gateway","card":{"cardholderName":"Test User","number":"5555555555554444","brand":"Mastercard","expMonth":"12","expYear":"2030","code":"456"},"notes":"SecretSpec test item"}' > /dev/null

    # 5. SSH Key Item: "Deploy SSH Key"
    ensure_item "Deploy SSH Key" '{"type":5,"name":"Deploy SSH Key","sshKey":{"privateKey":"-----BEGIN OPENSSH PRIVATE KEY-----\nfake_key_for_testing\n-----END OPENSSH PRIVATE KEY-----","publicKey":"ssh-rsa AAAAfake","keyFingerprint":"SHA256:fak3f1ng3rpr1nt"},"fields":[{"name":"passphrase","value":"ssh_passphrase_123","type":1}],"notes":"SecretSpec test item"}' > /dev/null

    # 6. Identity Item: "Employee Record"
    ensure_item "Employee Record" '{"type":4,"name":"Employee Record","identity":{"title":null,"firstName":"Test","middleName":null,"lastName":"Employee","username":null,"company":null,"email":"test.employee@example.com","phone":null},"fields":[{"name":"employee_id","value":"EMP001","type":1}],"notes":"SecretSpec test item"}' > /dev/null

    # 7. Secure Note Item: "Note to Self"
    ensure_item "Note to Self" '{"type":2,"name":"Note to Self","notes":"this is a note.","secureNote":{"type":0},"fields":[{"name":"value","value":"this is a note.","type":1}]}' > /dev/null

    echo -e "${GREEN}✓ Test data ready (${#CREATED_ITEM_IDS[@]} items created)${NC}"
}

# Clean up test data
cleanup_test_data() {
    if [ "$KEEP_TEST_DATA" = true ]; then
        echo -e "\n${YELLOW}--keep-test-data set, skipping cleanup${NC}"
        return
    fi
    echo -e "\n${YELLOW}Cleaning up test data...${NC}"
    for id in "${CREATED_ITEM_IDS[@]}"; do
        BW_SESSION="$BW_SESSION" bw delete item "$id" 2>/dev/null && echo "   Deleted $id" || true
    done
    # Also clean up any items we created during set tests
    local set_items
    set_items=$(BW_SESSION="$BW_SESSION" bw list items --search "bw_integration_test_" 2>/dev/null | \
        python3 -c "import sys,json; [print(i['id']) for i in json.load(sys.stdin)]" 2>/dev/null || true)
    for id in $set_items; do
        BW_SESSION="$BW_SESSION" bw delete item "$id" 2>/dev/null && echo "   Deleted $id (set test)" || true
    done
    echo -e "${GREEN}✓ Cleanup complete${NC}"
}

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

# Auto-create test items if they don't exist
setup_test_data
trap cleanup_test_data EXIT

# Create a test secretspec.toml
echo -e "\n${YELLOW}Setting up test configuration${NC}"
cat > secretspec.toml << 'EOF'
[project]
name = "bitwarden-test"
revision = "1.0"

[profiles.default]
# Keys use valid identifiers with ref mapping to Bitwarden item names
bw_integration_test_database = { required = true, description = "Login item password", ref = { item = "Test Database" } }
bw_integration_test_database_api_key = { required = true, description = "Login item custom field", ref = { item = "Test Database", field = "api_key" } }
bw_integration_test_database_username = { required = true, description = "Login item username", ref = { item = "Test Database", field = "username" } }
bw_integration_test_github_api = { required = true, description = "GitHub token", ref = { item = "GitHub API" } }
bw_integration_test_stripe_card_api_key = { required = true, description = "Card custom field", ref = { item = "Stripe Test Card", field = "api_key" } }
bw_integration_test_stripe_card_number = { required = true, description = "Card number field", ref = { item = "Stripe Test Card", field = "number" } }
bw_integration_test_payment_gateway = { required = true, description = "Card default field", ref = { item = "Payment Gateway" } }
bw_integration_test_employee_id = { required = true, description = "Identity custom field", ref = { item = "Employee Record", field = "employee_id" } }
bw_integration_test_employee_email = { required = true, description = "Identity email field", ref = { item = "Employee Record", field = "email" } }
bw_integration_test_deploy_ssh_key = { required = true, description = "SSH private key", ref = { item = "Deploy SSH Key" } }
bw_integration_test_ssh_passphrase = { required = true, description = "SSH passphrase", ref = { item = "Deploy SSH Key", field = "passphrase" } }
bw_integration_test_note_to_self = { required = true, description = "Secure note value", ref = { item = "Note to Self" } }

# Additional test secrets (optional)
bw_integration_test_nonexistent = { required = false, description = "Key that should not exist" }

EOF

echo -e "${GREEN}✓ Created test secretspec.toml${NC}"

# Build the binary first to avoid warnings during tests
echo -e "\n${YELLOW}Building secretspec binary...${NC}"
cargo build --bin secretspec --quiet
echo -e "${GREEN}✓ Binary built successfully${NC}"

echo -e "\n${YELLOW}=== PASSWORD MANAGER TESTS ===${NC}"

# Test 1: Login Items - Default password field (Test Database)
run_test "Get password from Login item" \
    "./target/debug/secretspec get bw_integration_test_database --provider bitwarden://" \
    "tets-db-password"

# Test 2: Login Items - Custom field (Test Database api_key)
run_test "Get api_key custom field from Login item" \
    "./target/debug/secretspec get bw_integration_test_database_api_key --provider bitwarden://" \
    "sk_test_db_12345"

# Test 3: Login Items - Username field (Test Database)
run_test "Get username field from Login item" \
    "./target/debug/secretspec get bw_integration_test_database_username --provider bitwarden://" \
    "testuser"

# Test 4: Credit Card Items - Custom field (Stripe Test Card)
run_test "Get api_key custom field from Credit Card item" \
    "./target/debug/secretspec get bw_integration_test_stripe_card_api_key --provider bitwarden://" \
    "sk_test_stripe_12345"

# Test 5: Credit Card Items - Standard field
run_test "Get card number field from Credit Card item" \
    "./target/debug/secretspec get bw_integration_test_stripe_card_number --provider bitwarden://" \
    "4242424242424242"

# Test 6: Identity Items - Custom field (field required)
run_test "Get employee_id field from Identity item" \
    "./target/debug/secretspec get bw_integration_test_employee_id --provider bitwarden://" \
    "EMP001"

# Test 7: Identity Items - Standard field
run_test "Get email field from Identity item" \
    "./target/debug/secretspec get bw_integration_test_employee_email --provider bitwarden://" \
    "test.employee@example.com"

# Test 8: SSH Key Items - Default field (private key)
run_test "Get private key from SSH Key item" \
    "./target/debug/secretspec get bw_integration_test_deploy_ssh_key --provider bitwarden://" \
    "BEGIN OPENSSH PRIVATE KEY"

# Test 9: SSH Key Items - Custom field
run_test "Get passphrase field from SSH Key item" \
    "./target/debug/secretspec get bw_integration_test_ssh_passphrase --provider bitwarden://" \
    "ssh_passphrase_123"

# Test 10: Secure Note Items - Get note contents
run_test "Get value from Secure Note item" \
    "./target/debug/secretspec get bw_integration_test_note_to_self --provider bitwarden://" \
    "this is a note."

echo -e "\n${YELLOW}=== ENVIRONMENT VARIABLE TESTS ===${NC}"

# Test 11: Environment variable for type
run_test "Get API key using environment variable type" \
    "BITWARDEN_DEFAULT_TYPE=card BITWARDEN_DEFAULT_FIELD=api_key ./target/debug/secretspec get bw_integration_test_stripe_card_api_key --provider bitwarden://" \
    "sk_test_stripe_12345"

# Test 12: Environment variable for field
run_test "Get username using environment variable field" \
    "BITWARDEN_DEFAULT_TYPE=login BITWARDEN_DEFAULT_FIELD=username ./target/debug/secretspec get bw_integration_test_database_username --provider bitwarden://" \
    "testuser"

# Test 13: One-liner with multiple environment variables
run_test "Get employee ID with environment variables" \
    "BITWARDEN_DEFAULT_TYPE=identity BITWARDEN_DEFAULT_FIELD=employee_id ./target/debug/secretspec get bw_integration_test_employee_id --provider bitwarden://" \
    "EMP001"

echo -e "\n${YELLOW}=== ERROR HANDLING TESTS ===${NC}"

# Test 14: Missing field specification for Card items
run_test "Card item without field specification returns default field" \
    "./target/debug/secretspec get bw_integration_test_payment_gateway --provider bitwarden://" \
    "5555555555554444"

# Test 15: Invalid item type should fail
run_test_expect_fail "Invalid item type should fail" \
    "./target/debug/secretspec get bw_test_nonexistent_item --provider 'bitwarden://?type=invalid'" \
    "not found"

# Test 16: Non-existent item
run_test_expect_fail "Non-existent item should return error or empty" \
    "./target/debug/secretspec get bw_integration_test_nonexistent --provider bitwarden://" \
    ""

echo -e "\n${YELLOW}=== ITEM CREATION TESTS ===${NC}"

# Sync vault before creation tests to avoid cipher conflicts
echo "Syncing Bitwarden vault..."
if ! BW_SESSION="$BW_SESSION" bw sync; then
    echo -e "${YELLOW}Warning: Vault sync failed, creation tests may fail${NC}"
fi

# Test 20: Create new Login item
run_test "Create new Login item" \
    "./target/debug/secretspec set bw_integration_test_new_login 'test-new-secret' --provider 'bitwarden://?type=login'" \
    "Secret.*saved"

# Test 21: Create new Card item with custom field
run_test "Create new Card item with custom field" \
    "./target/debug/secretspec set bw_integration_test_new_card 'test-card-token' --provider 'bitwarden://?type=card&field=api_token'" \
    "Secret.*saved"

# Test 22: Update existing item
run_test "Update existing Login item" \
    "./target/debug/secretspec set bw_integration_test_database 'updated-password' --provider bitwarden://" \
    "Secret.*saved"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 ALL TESTS PASSED!${NC}"
    echo "The Bitwarden provider is working correctly with real vault data."
else
    echo -e "\n${RED}❌ SOME TESTS FAILED${NC}"
    echo "Please review the failed tests above."
fi

# Cleanup test config file (items cleaned up by EXIT trap)
rm -f secretspec.toml

echo -e "\n${BLUE}Testing complete!${NC}"
