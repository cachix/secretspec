#!/bin/bash

# SecretSpec Bitwarden Integration Test Script
# Tests the Bitwarden provider against actual vault data
# Usage: ./bitwarden_integration.sh [BW_SESSION]
#
# The script auto-creates test items if they don't exist,
# and removes them on clean exit (unless --keep-test-data is passed).
#
# FUTURE WORK: full automation via vaultwarden
# ---------------------------------------------
# This script currently requires a real, unlocked vault (BW_SESSION), so a
# human with a Bitwarden account is always in the loop. The ultimate way to
# automate it is to run against a local vaultwarden server (a
# Bitwarden-compatible reimplementation) instead of the real cloud:
#
#   docker run --rm -p 8087:80 -e SIGNUPS_ALLOWED=true vaultwarden/server
#   bw config server http://localhost:8087
#   # bootstrap a throwaway fixture account, login, unlock, export BW_SESSION
#
# With a local, disposable server the account credentials become committable
# test fixtures rather than secrets: any dev can run the test with zero
# setup, and CI (including fork PRs) needs no repository secrets. Fidelity
# stays high because the genuine `bw` CLI is still the client under test.
# vaultwarden is also packaged in nixpkgs (pkgs.vaultwarden), so the devenv
# shell could provide it as a plain binary, no Docker required.
#
# Caveats: `bw` has no `register` command, so account bootstrap needs either
# a call to the registration API or a pre-seeded SQLite db fixture; and since
# vaultwarden is not the official server, an occasional manual run against
# real Bitwarden cloud would still be worth keeping.
#
# FUTURE WORK: absorbing the sibling bw scripts
# ---------------------------------------------
# There are now three bw test scripts, and vaultwarden_harness.sh invokes each
# of them separately:
#
#   bitwarden_integration.sh            this file — the broad behavioral suite
#   bitwarden_regression_findings.sh    the PR #166 review findings (R1-R4)
#   bitwarden_collection_addressing.sh  organization/collection addressing (C3)
#
# Folding the latter two in here would give one entry point and one summary.
# They should be *invoked*, never copied: each owns fixtures the others do not,
# and duplicating assertions is how the two of them would drift apart. What it
# would take:
#
#   - Reconcile the shell contracts. This script uses `set -e`; both siblings
#     use `set -uo pipefail` and deliberately exit non-zero to report failures.
#     Called directly, that designed exit would kill this script mid-suite, so
#     the call has to run with `set +e` and capture the status.
#   - Fold the counters rather than merge them. This script counts
#     TESTS_RUN/TESTS_PASSED/TESTS_FAILED through run_test; the regression
#     script counts FIXED/REPRODUCED through its own `report`. The practical
#     conversion is one parent-level pass/fail per child, with the child's own
#     output echoed through for detail.
#   - Contain the working directory. Each sibling mktemps a directory, cd's
#     into it, and writes its own secretspec.toml; this script writes
#     secretspec.toml into the current directory. Running a child in a subshell
#     keeps its `cd` from leaking into the tests that follow.
#   - Keep the EXIT traps apart. All three install `trap cleanup EXIT`. In a
#     subshell the child's trap fires on its own exit, which is correct, but
#     this script's cleanup_test_data must not delete items the child is still
#     using — so children run to completion between parent test groups, never
#     alongside them.
#   - Respect the preconditions. Both siblings need target/debug/secretspec,
#     which this script builds, so they can only run after that step.
#     bitwarden_collection_addressing.sh additionally needs the organization
#     fixture (BW_TEST_ORG_ID and friends) and skips itself without it.
#
# Sketch:
#
#   run_subscript() {   # run_subscript <name> <script-path>
#       TESTS_RUN=$((TESTS_RUN + 1))
#       echo -e "\n${BLUE}Test $TESTS_RUN: $1${NC}"
#       if ( set +e; bash "$2" </dev/null ); then
#           TESTS_PASSED=$((TESTS_PASSED + 1))
#       else
#           TESTS_FAILED=$((TESTS_FAILED + 1))
#       fi
#   }
#
# with RUN_REGRESSIONS and BW_TEST_ORG_ID gating which children are called.
#
set -e  # Exit on any error

# `[project].require_reason` defaults to "agents", so every get/set below is
# policy-denied when this script runs under a coding agent — turning the whole
# suite red for a reason that has nothing to do with the provider. Declaring
# the reason is the intended way through the gate (as opposed to disabling the
# policy); an explicit SECRETSPEC_REASON from the caller still wins.
export SECRETSPEC_REASON="${SECRETSPEC_REASON:-bw provider integration test suite}"

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

# Every fixture name starts with this, so nothing here can collide with an
# ordinary vault entry. The names used to be things like "Test Database" and
# "GitHub API" -- plausible enough in a real vault that this suite, which the
# header above advertises running against one, could pick a user's own item up
# as a fixture and then overwrite its password.
FIXTURE_PREFIX="${BW_FIXTURE_PREFIX:-secretspec-it}"

FX_DATABASE="$FIXTURE_PREFIX Test Database"
FX_GITHUB="$FIXTURE_PREFIX GitHub API"
FX_STRIPE="$FIXTURE_PREFIX Stripe Test Card"
FX_GATEWAY="$FIXTURE_PREFIX Payment Gateway"
FX_SSH="$FIXTURE_PREFIX Deploy SSH Key"
FX_EMPLOYEE="$FIXTURE_PREFIX Employee Record"
FX_NOTE="$FIXTURE_PREFIX Note to Self"

# Create a BW item from the given JSON template and record its ID.
#
# Refuses to run if the name is already taken. Adopting a pre-existing item was
# the actual data-loss path: the id never reached CREATED_ITEM_IDS, so cleanup
# neither deleted nor restored it, while the tests below happily wrote to it.
# The prefix makes a collision unlikely; this makes it harmless.
ensure_item() {
    local name="$1"
    local template_json="$2"

    # Check if item already exists
    local existing_id
    existing_id=$(BW_SESSION="$BW_SESSION" bw list items --search "$name" 2>/dev/null | \
        python3 -c "import sys,json; items=[i for i in json.load(sys.stdin) if i.get('name','')=='$name']; print(items[0]['id'] if items else '')" 2>/dev/null || true)

    if [ -n "$existing_id" ]; then
        # Disarm cleanup before leaving. Today the EXIT trap is installed after
        # setup_test_data, so aborting here happens to touch nothing -- but the
        # sweep matches on the fixture prefix, which is exactly what this item
        # is named. Moving that trap earlier would turn this safety check into
        # a delete of the very item it is refusing to modify, so do not depend
        # on the ordering.
        ABORTED_ON_COLLISION=true
        echo "" >&2
        echo "ERROR: a vault item is already named '$name' ($existing_id)." >&2
        echo "This suite mutates its fixtures, so it will not touch an item it" >&2
        echo "did not create. Delete or rename that item, or set" >&2
        echo "BW_FIXTURE_PREFIX to something unused, then re-run." >&2
        exit 1
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
    ensure_item "$FX_DATABASE" "{\"type\":1,\"name\":\"${FX_DATABASE}\",\"login\":{\"username\":\"testuser\",\"password\":\"test-db-password\",\"totp\":null,\"uris\":[]},\"fields\":[{\"name\":\"api_key\",\"value\":\"sk_test_db_12345\",\"type\":1}],\"notes\":\"SecretSpec test item\"}" > /dev/null

    # 2. Login Item: "GitHub API"
    ensure_item "$FX_GITHUB" "{\"type\":1,\"name\":\"${FX_GITHUB}\",\"login\":{\"username\":\"testuser\",\"password\":\"ghp_fake_token_for_testing\",\"totp\":null,\"uris\":[]},\"notes\":\"SecretSpec test item\"}" > /dev/null

    # 3. Card Item: "Stripe Test Card"
    ensure_item "$FX_STRIPE" "{\"type\":3,\"name\":\"${FX_STRIPE}\",\"card\":{\"cardholderName\":\"Test User\",\"number\":\"4242424242424242\",\"brand\":\"Visa\",\"expMonth\":\"12\",\"expYear\":\"2030\",\"code\":\"123\"},\"fields\":[{\"name\":\"api_key\",\"value\":\"sk_test_stripe_12345\",\"type\":1}],\"notes\":\"SecretSpec test item\"}" > /dev/null

    # 4. Card Item: "Payment Gateway"
    ensure_item "$FX_GATEWAY" "{\"type\":3,\"name\":\"${FX_GATEWAY}\",\"card\":{\"cardholderName\":\"Test User\",\"number\":\"5555555555554444\",\"brand\":\"Mastercard\",\"expMonth\":\"12\",\"expYear\":\"2030\",\"code\":\"456\"},\"notes\":\"SecretSpec test item\"}" > /dev/null

    # 5. SSH Key Item: "Deploy SSH Key"
    ensure_item "$FX_SSH" "{\"type\":5,\"name\":\"${FX_SSH}\",\"sshKey\":{\"privateKey\":\"-----BEGIN OPENSSH PRIVATE KEY-----\\nfake_key_for_testing\\n-----END OPENSSH PRIVATE KEY-----\",\"publicKey\":\"ssh-rsa AAAAfake\",\"keyFingerprint\":\"SHA256:fak3f1ng3rpr1nt\"},\"fields\":[{\"name\":\"passphrase\",\"value\":\"ssh_passphrase_123\",\"type\":1}],\"notes\":\"SecretSpec test item\"}" > /dev/null

    # 6. Identity Item: "Employee Record"
    ensure_item "$FX_EMPLOYEE" "{\"type\":4,\"name\":\"${FX_EMPLOYEE}\",\"identity\":{\"title\":null,\"firstName\":\"Test\",\"middleName\":null,\"lastName\":\"Employee\",\"username\":null,\"company\":null,\"email\":\"test.employee@example.com\",\"phone\":null},\"fields\":[{\"name\":\"employee_id\",\"value\":\"EMP001\",\"type\":1}],\"notes\":\"SecretSpec test item\"}" > /dev/null

    # 7. Secure Note Item: "Note to Self"
    ensure_item "$FX_NOTE" "{\"type\":2,\"name\":\"${FX_NOTE}\",\"notes\":\"this is a note.\",\"secureNote\":{\"type\":0},\"fields\":[{\"name\":\"value\",\"value\":\"this is a note.\",\"type\":1}]}" > /dev/null

    echo -e "${GREEN}✓ Test data ready (${#CREATED_ITEM_IDS[@]} items created)${NC}"
}

# Set when ensure_item refuses to adopt a pre-existing item. Cleanup is a no-op
# afterwards: the run owns nothing, and the thing that stopped it is a vault
# item belonging to someone else.
ABORTED_ON_COLLISION=false

# Clean up test data
cleanup_test_data() {
    if [ "$ABORTED_ON_COLLISION" = true ]; then
        echo -e "\n${YELLOW}Aborted on a name collision; leaving the vault untouched${NC}" >&2
        return
    fi
    if [ "$KEEP_TEST_DATA" = true ]; then
        echo -e "\n${YELLOW}--keep-test-data set, skipping cleanup${NC}"
        return
    fi
    echo -e "\n${YELLOW}Cleaning up test data...${NC}"
    for id in "${CREATED_ITEM_IDS[@]}"; do
        BW_SESSION="$BW_SESSION" bw delete item "$id" 2>/dev/null && echo "   Deleted $id" || true
    done
    # Also clean up items the `set` tests created, which are named after the
    # secret rather than through ensure_item, plus any fixture left behind by a
    # run that died before its trap fired.
    #
    # The name has to *start with* one of the prefixes. `bw list --search` is a
    # substring match over names, usernames, URIs and notes, so filtering on its
    # results alone would delete any vault item that merely mentions the prefix
    # somewhere -- an unpleasant thing for a cleanup routine to do to a real
    # vault.
    local sweepable
    sweepable=$(BW_SESSION="$BW_SESSION" bw list items 2>/dev/null | \
        python3 -c "
import sys, json
prefixes = ('bw_integration_test_', $(printf '%s' "\"$FIXTURE_PREFIX\""))
for item in json.load(sys.stdin):
    if item.get('name', '').startswith(prefixes):
        print(item['id'])
" 2>/dev/null || true)
    for id in $sweepable; do
        BW_SESSION="$BW_SESSION" bw delete item "$id" 2>/dev/null && echo "   Deleted $id (swept)" || true
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
#
# This lands in the *current* directory, and vaultwarden_harness.sh runs this
# script from the repository root. Writing it unconditionally and then `rm -f`ing
# it on the way out already destroyed one config that way: the repository used to
# check a secretspec.toml in at the root (deleted here, restored in 859ef5e;
# upstream has since removed it for good in a479b4f).
#
# That file being gone does not make the unconditional write safe. Anyone
# dogfooding secretspec inside its own checkout can have an untracked
# secretspec.toml in exactly that spot, and upstream's own tests/cli-integration.sh
# writes one there too. So move any existing file aside first and put it back on
# exit, and let the guard stay a no-op when there is nothing to protect.
echo -e "\n${YELLOW}Setting up test configuration${NC}"
SAVED_CONFIG=""
if [ -e secretspec.toml ]; then
    SAVED_CONFIG=$(mktemp)
    cp secretspec.toml "$SAVED_CONFIG"
    echo "   Preserving existing secretspec.toml for the duration of the run"
fi
restore_config() {
    rm -f secretspec.toml
    if [ -n "$SAVED_CONFIG" ]; then
        mv "$SAVED_CONFIG" secretspec.toml
    fi
}
trap 'cleanup_test_data; restore_config' EXIT
cat > secretspec.toml << EOF
[project]
name = "bitwarden-test"
revision = "1.0"

[profiles.default]
# Keys use valid identifiers with ref mapping to Bitwarden item names
bw_integration_test_database = { required = true, description = "Login item password", ref = { item = "${FX_DATABASE}" } }
bw_integration_test_database_api_key = { required = true, description = "Login item custom field", ref = { item = "${FX_DATABASE}", field = "api_key" } }
bw_integration_test_database_username = { required = true, description = "Login item username", ref = { item = "${FX_DATABASE}", field = "username" } }
bw_integration_test_github_api = { required = true, description = "GitHub token", ref = { item = "${FX_GITHUB}" } }
bw_integration_test_stripe_card_api_key = { required = true, description = "Card custom field", ref = { item = "${FX_STRIPE}", field = "api_key" } }
bw_integration_test_stripe_card_number = { required = true, description = "Card number field", ref = { item = "${FX_STRIPE}", field = "number" } }
bw_integration_test_payment_gateway = { required = true, description = "Card default field", ref = { item = "${FX_GATEWAY}" } }
bw_integration_test_employee_id = { required = true, description = "Identity custom field", ref = { item = "${FX_EMPLOYEE}", field = "employee_id" } }
bw_integration_test_employee_email = { required = true, description = "Identity email field", ref = { item = "${FX_EMPLOYEE}", field = "email" } }
bw_integration_test_deploy_ssh_key = { required = true, description = "SSH private key", ref = { item = "${FX_SSH}" } }
bw_integration_test_ssh_passphrase = { required = true, description = "SSH passphrase", ref = { item = "${FX_SSH}", field = "passphrase" } }
bw_integration_test_note_to_self = { required = true, description = "Secure note value", ref = { item = "${FX_NOTE}" } }

# Additional test secrets (optional)
bw_integration_test_nonexistent = { required = false, description = "Key that should not exist" }
bw_test_nonexistent_item = { required = false, description = "Item that definitely should not exist" }
bw_integration_test_new_login = { required = false, description = "Login item for creation test" }
bw_integration_test_new_card = { required = false, description = "Card item for creation test" }

# One per item type for the create -> update -> read-back sweep. Deliberately
# no `ref`: the item is named after the key, so the provider both creates and
# later finds it on its own terms rather than against a hand-built fixture.
bw_integration_test_roundtrip_login = { required = false, description = "Round-trip: login" }
bw_integration_test_roundtrip_note = { required = false, description = "Round-trip: secure note" }
bw_integration_test_roundtrip_card = { required = false, description = "Round-trip: card" }
bw_integration_test_roundtrip_identity = { required = false, description = "Round-trip: identity" }
bw_integration_test_roundtrip_ssh = { required = false, description = "Round-trip: SSH key" }

EOF

echo -e "${GREEN}✓ Created test secretspec.toml${NC}"

# Build the binary first to avoid warnings during tests
echo -e "\n${YELLOW}Building secretspec binary...${NC}"
cargo build --bin secretspec --quiet
echo -e "${GREEN}✓ Binary built successfully${NC}"

echo -e "\n${YELLOW}=== PASSWORD MANAGER TESTS ===${NC}"

# Test 1: Login Items - Default password field (Test Database)
run_test "Get password from Login item" \
    "./target/debug/secretspec get bw_integration_test_database --provider bw://" \
    "test-db-password"

# Test 2: Login Items - Custom field (Test Database api_key)
run_test "Get api_key custom field from Login item" \
    "./target/debug/secretspec get bw_integration_test_database_api_key --provider bw://" \
    "sk_test_db_12345"

# Test 3: Login Items - Username field (Test Database)
run_test "Get username field from Login item" \
    "./target/debug/secretspec get bw_integration_test_database_username --provider bw://" \
    "testuser"

# Test 4: Credit Card Items - Custom field (Stripe Test Card)
run_test "Get api_key custom field from Credit Card item" \
    "./target/debug/secretspec get bw_integration_test_stripe_card_api_key --provider bw://" \
    "sk_test_stripe_12345"

# Test 5: Credit Card Items - Standard field
run_test "Get card number field from Credit Card item" \
    "./target/debug/secretspec get bw_integration_test_stripe_card_number --provider bw://" \
    "4242424242424242"

# Test 6: Identity Items - Custom field (field required)
run_test "Get employee_id field from Identity item" \
    "./target/debug/secretspec get bw_integration_test_employee_id --provider bw://" \
    "EMP001"

# Test 7: Identity Items - Standard field
run_test "Get email field from Identity item" \
    "./target/debug/secretspec get bw_integration_test_employee_email --provider bw://" \
    "test.employee@example.com"

# Test 8: SSH Key Items - Default field (private key)
run_test "Get private key from SSH Key item" \
    "./target/debug/secretspec get bw_integration_test_deploy_ssh_key --provider bw://" \
    "BEGIN OPENSSH PRIVATE KEY"

# Test 9: SSH Key Items - Custom field
run_test "Get passphrase field from SSH Key item" \
    "./target/debug/secretspec get bw_integration_test_ssh_passphrase --provider bw://" \
    "ssh_passphrase_123"

# Test 10: Secure Note Items - Get note contents
run_test "Get value from Secure Note item" \
    "./target/debug/secretspec get bw_integration_test_note_to_self --provider bw://" \
    "this is a note."

echo -e "\n${YELLOW}=== ENVIRONMENT VARIABLE TESTS ===${NC}"

# Test 11: Environment variable for type
run_test "Get API key using environment variable type" \
    "BITWARDEN_DEFAULT_TYPE=card BITWARDEN_DEFAULT_FIELD=api_key ./target/debug/secretspec get bw_integration_test_stripe_card_api_key --provider bw://" \
    "sk_test_stripe_12345"

# Test 12: Environment variable for field
run_test "Get username using environment variable field" \
    "BITWARDEN_DEFAULT_TYPE=login BITWARDEN_DEFAULT_FIELD=username ./target/debug/secretspec get bw_integration_test_database_username --provider bw://" \
    "testuser"

# Test 13: One-liner with multiple environment variables
run_test "Get employee ID with environment variables" \
    "BITWARDEN_DEFAULT_TYPE=identity BITWARDEN_DEFAULT_FIELD=employee_id ./target/debug/secretspec get bw_integration_test_employee_id --provider bw://" \
    "EMP001"

echo -e "\n${YELLOW}=== ERROR HANDLING TESTS ===${NC}"

# Test 14: Missing field specification for Card items
run_test "Card item without field specification returns default field" \
    "./target/debug/secretspec get bw_integration_test_payment_gateway --provider bw://" \
    "5555555555554444"

# Test 15: Invalid item type is rejected when the address is parsed.
# It used to fail only incidentally, because the item did not exist either; now
# the typo itself is what is reported.
run_test_expect_fail "Invalid item type should fail" \
    "./target/debug/secretspec get bw_test_nonexistent_item --provider 'bw://?type=invalid'" \
    "Unknown Bitwarden item type"

# Test 15b: an unknown query parameter is likewise a typo, not a no-op
run_test_expect_fail "Unknown query parameter should fail" \
    "./target/debug/secretspec get bw_test_nonexistent_item --provider 'bw://?feild=api_key'" \
    "Unknown Bitwarden URI parameter"

# Test 16: Non-existent item
run_test_expect_fail "Non-existent item should return error or empty" \
    "./target/debug/secretspec get bw_integration_test_nonexistent --provider bw://" \
    ""

echo -e "\n${YELLOW}=== ITEM CREATION TESTS ===${NC}"

# Sync vault before creation tests to avoid cipher conflicts
echo "Syncing Bitwarden vault..."
if ! BW_SESSION="$BW_SESSION" bw sync; then
    echo -e "${YELLOW}Warning: Vault sync failed, creation tests may fail${NC}"
fi

# Test 20: Create new Login item
run_test "Create new Login item" \
    "./target/debug/secretspec set bw_integration_test_new_login 'test-new-secret' --provider 'bw://?type=login'" \
    "Secret.*saved"

# Test 21: Create new Card item with custom field
run_test "Create new Card item with custom field" \
    "./target/debug/secretspec set bw_integration_test_new_card 'test-card-token' --provider 'bw://?type=card&field=api_token'" \
    "Secret.*saved"

# Test 22: Update existing item
run_test "Update existing Login item" \
    "./target/debug/secretspec set bw_integration_test_database 'updated-password' --provider bw://" \
    "Secret.*saved"

echo -e "\n${YELLOW}=== CREATE → UPDATE → READ-BACK SWEEP ===${NC}"
# Every other fixture in this file is built with raw `bw`, so nothing above
# reads an item that secretspec itself created. That is the gap R2 lived in:
# `set` reported success while writing the value somewhere `get` would never
# look, and an assertion on "Secret ... saved" cannot tell the difference.
#
# For each item type: create through the provider, read it back, update the
# item the provider just made, and read it back again. The update leg matters
# as much as the create -- test 19 above updates an item `ensure_item` built,
# so the writer has never been pointed at its own output.
roundtrip_type() {
    local label="$1"
    local type="$2"
    local secret="bw_integration_test_roundtrip_${label}"
    local created="created-${label}-value"
    local updated="updated-${label}-value"

    run_test "Round-trip ${label}: set creates the item" \
        "./target/debug/secretspec set $secret '$created' --provider 'bw://?type=$type'" \
        "Secret.*saved"

    run_test "Round-trip ${label}: get returns what set wrote" \
        "./target/debug/secretspec get $secret --provider 'bw://?type=$type'" \
        "$created"

    run_test "Round-trip ${label}: set updates its own item" \
        "./target/debug/secretspec set $secret '$updated' --provider 'bw://?type=$type'" \
        "Secret.*saved"

    # Fails if the update landed in a different field than the getter reads,
    # or created a duplicate item alongside the original.
    run_test "Round-trip ${label}: get reflects the update" \
        "./target/debug/secretspec get $secret --provider 'bw://?type=$type'" \
        "$updated"
}

roundtrip_type login login
roundtrip_type note note
roundtrip_type card card
roundtrip_type identity identity
roundtrip_type ssh ssh

# Test items and the test config are both cleaned up by the EXIT trap, which
# also restores any secretspec.toml that was here before the run.

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 ALL TESTS PASSED!${NC}"
    echo "The Bitwarden provider is working correctly with real vault data."
    echo -e "\n${BLUE}Testing complete!${NC}"
    exit 0
fi

echo -e "\n${RED}❌ $TESTS_FAILED of $TESTS_RUN TESTS FAILED${NC}"
echo "Please review the failed tests above."

# `run_test` records failures in a counter rather than letting them propagate,
# so `set -e` never sees them and the script used to end on a successful `echo`.
# vaultwarden_harness.sh reads this status, so returning 0 here made the whole
# documented harness incapable of failing on a provider regression. The EXIT
# trap still runs and does not itself call `exit`, so this status survives it.
exit 1
