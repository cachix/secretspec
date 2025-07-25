#!/bin/bash

# SecretSpec Bitwarden Performance Analysis Script
# Measures timing of different Bitwarden CLI operations
# Usage: ./bitwarden_performance.sh [BW_SESSION]

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

echo "🔬 SecretSpec Bitwarden Performance Analysis"
echo "==========================================="

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
NC='\033[0m' # No Color

# Timing variables
declare -a TIMING_LABELS
declare -a TIMING_VALUES
TIMING_COUNT=0

# Function to measure command execution time
measure_time() {
    local label="$1"
    local command="$2"
    
    echo -e "\n${BLUE}Measuring: $label${NC}"
    echo "Command: $command"
    
    # Measure execution time using time command
    local start_time=$(date +%s%N)
    
    if output=$(eval "$command" 2>&1); then
        local end_time=$(date +%s%N)
        local duration_ns=$((end_time - start_time))
        local duration_ms=$((duration_ns / 1000000))
        
        echo -e "${GREEN}✓ Success${NC} - Duration: ${duration_ms}ms"
        
        # Store timing data
        TIMING_LABELS[$TIMING_COUNT]="$label"
        TIMING_VALUES[$TIMING_COUNT]=$duration_ms
        TIMING_COUNT=$((TIMING_COUNT + 1))
        
        # Show output size
        local output_size=${#output}
        echo "Output size: $output_size bytes"
    else
        echo -e "${RED}✗ Failed${NC}: $output"
    fi
}

# Function to measure repeated operations
measure_repeated() {
    local label="$1"
    local command="$2"
    local count="${3:-5}"  # Default to 5 iterations
    
    echo -e "\n${MAGENTA}Measuring repeated: $label (${count}x)${NC}"
    echo "Command: $command"
    
    local total_time=0
    local min_time=999999
    local max_time=0
    
    for i in $(seq 1 $count); do
        local start_time=$(date +%s%N)
        
        if eval "$command" >/dev/null 2>&1; then
            local end_time=$(date +%s%N)
            local duration_ns=$((end_time - start_time))
            local duration_ms=$((duration_ns / 1000000))
            
            total_time=$((total_time + duration_ms))
            
            if [ $duration_ms -lt $min_time ]; then
                min_time=$duration_ms
            fi
            
            if [ $duration_ms -gt $max_time ]; then
                max_time=$duration_ms
            fi
            
            echo -n "."
        else
            echo -e "\n${RED}✗ Failed on iteration $i${NC}"
            return 1
        fi
    done
    
    local avg_time=$((total_time / count))
    
    echo -e "\n${GREEN}✓ Completed${NC}"
    echo "Average: ${avg_time}ms, Min: ${min_time}ms, Max: ${max_time}ms"
    
    # Store average timing data
    TIMING_LABELS[$TIMING_COUNT]="$label (avg)"
    TIMING_VALUES[$TIMING_COUNT]=$avg_time
    TIMING_COUNT=$((TIMING_COUNT + 1))
}

echo -e "\n${YELLOW}Prerequisites Check${NC}"
echo "Checking Bitwarden CLI authentication..."

# Check BW authentication
if ! BW_SESSION="$BW_SESSION" bw status | grep -q "unlocked"; then
    echo -e "${RED}ERROR: Bitwarden vault is not unlocked with provided session!${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Bitwarden CLI is authenticated and unlocked${NC}"

# Get vault size for context
echo -e "\n${YELLOW}Vault Statistics${NC}"
item_count=$(BW_SESSION="$BW_SESSION" bw list items | jq 'length')
echo "Total items in vault: $item_count"

# Create test items if needed
echo -e "\n${YELLOW}Setting up test data${NC}"
TEST_ITEM_NAME="secretspec-perf-test-$(date +%s)"
echo "Creating test item: $TEST_ITEM_NAME"

# Create a test item
create_json=$(cat <<EOF
{
  "type": 1,
  "name": "$TEST_ITEM_NAME",
  "login": {
    "username": "testuser",
    "password": "testpassword"
  },
  "fields": [
    {"name": "api_key", "value": "sk_test_12345", "type": 0},
    {"name": "secret_token", "value": "token_67890", "type": 1}
  ]
}
EOF
)

encoded_json=$(echo "$create_json" | base64 | tr -d '\n')
BW_SESSION="$BW_SESSION" bw create item "$encoded_json" >/dev/null
echo -e "${GREEN}✓ Test item created${NC}"

echo -e "\n${YELLOW}=== BITWARDEN CLI PERFORMANCE TESTS ===${NC}"

# Test 1: Basic status check
measure_time "bw status" \
    "BW_SESSION='$BW_SESSION' bw status"

# Test 2: List all items (full vault scan)
measure_time "bw list items (full vault)" \
    "BW_SESSION='$BW_SESSION' bw list items"

# Test 3: List items with search filter
measure_time "bw list items --search (filtered)" \
    "BW_SESSION='$BW_SESSION' bw list items --search '$TEST_ITEM_NAME'"

# Test 4: Get specific item by exact name
measure_time "bw get item (by name)" \
    "BW_SESSION='$BW_SESSION' bw get item '$TEST_ITEM_NAME'"

# Test 5: List + jq filtering (current implementation)
measure_time "bw list + jq filter" \
    "BW_SESSION='$BW_SESSION' bw list items | jq -r '.[] | select(.name == \"$TEST_ITEM_NAME\")'"

# Test 6: List with search + jq (optimized)
measure_time "bw list --search + jq" \
    "BW_SESSION='$BW_SESSION' bw list items --search '$TEST_ITEM_NAME' | jq -r '.[0]'"

echo -e "\n${YELLOW}=== REPEATED OPERATION TESTS ===${NC}"

# Test 7: Repeated item retrieval (cache effectiveness)
measure_repeated "Repeated bw get item" \
    "BW_SESSION='$BW_SESSION' bw get item '$TEST_ITEM_NAME'" \
    10

# Test 8: Repeated list + search
measure_repeated "Repeated bw list --search" \
    "BW_SESSION='$BW_SESSION' bw list items --search '$TEST_ITEM_NAME'" \
    10

echo -e "\n${YELLOW}=== FIELD EXTRACTION PERFORMANCE ===${NC}"

# Test 9: Extract password field with jq
measure_time "Extract password with jq" \
    "BW_SESSION='$BW_SESSION' bw get item '$TEST_ITEM_NAME' | jq -r '.login.password'"

# Test 10: Extract custom field with jq
measure_time "Extract custom field with jq" \
    "BW_SESSION='$BW_SESSION' bw get item '$TEST_ITEM_NAME' | jq -r '.fields[] | select(.name == \"api_key\") | .value'"

echo -e "\n${YELLOW}=== LARGE RESPONSE TESTS ===${NC}"

# Test 11: Search with common prefix (potentially many results)
measure_time "Search common prefix" \
    "BW_SESSION='$BW_SESSION' bw list items --search 'test'"

# Test 12: Process large JSON response
measure_time "Process vault JSON size" \
    "BW_SESSION='$BW_SESSION' bw list items | wc -c"

echo -e "\n${YELLOW}=== SECRETSPEC INTEGRATION PERFORMANCE ===${NC}"

# Enable performance logging for detailed timing
export SECRETSPEC_PERF_LOG=1
echo "Performance logging enabled - will show detailed timing breakdown"

# Create a test secretspec.toml
cat > secretspec.toml << EOF
[project]
name = "perf-test"
revision = "1.0"

[profiles.default]
"$TEST_ITEM_NAME" = { required = true }
TEST_FIELD = { required = false }
EOF

# Build if needed
if [ ! -f "./target/debug/secretspec" ]; then
    echo "Building secretspec..."
    cargo build --bin secretspec --quiet
fi

# Test 13: SecretSpec get (password field) - with detailed logging
echo -e "\n${BLUE}Detailed timing for secretspec get operation:${NC}"
echo "This will show breakdown of CLI vs JSON processing time:"
measure_time "secretspec get (password)" \
    "BW_SESSION='$BW_SESSION' SECRETSPEC_PERF_LOG=1 ./target/debug/secretspec get '$TEST_ITEM_NAME' --provider 'bitwarden://'" | tee /tmp/secretspec_timing.log

# Test 14: SecretSpec get (custom field)
measure_time "secretspec get (custom field)" \
    "BW_SESSION='$BW_SESSION' ./target/debug/secretspec get '$TEST_ITEM_NAME' --provider 'bitwarden://?field=api_key'"

# Test 15: Repeated SecretSpec operations
measure_repeated "Repeated secretspec get" \
    "BW_SESSION='$BW_SESSION' ./target/debug/secretspec get '$TEST_ITEM_NAME' --provider 'bitwarden://'" \
    10

echo -e "\n${YELLOW}=== PERFORMANCE SUMMARY ===${NC}"
echo "=========================================="

# Find slowest and fastest operations
slowest_idx=0
fastest_idx=0
slowest_time=0
fastest_time=999999

for i in $(seq 0 $((TIMING_COUNT - 1))); do
    if [ ${TIMING_VALUES[$i]} -gt $slowest_time ]; then
        slowest_time=${TIMING_VALUES[$i]}
        slowest_idx=$i
    fi
    
    if [ ${TIMING_VALUES[$i]} -lt $fastest_time ]; then
        fastest_time=${TIMING_VALUES[$i]}
        fastest_idx=$i
    fi
done

echo -e "\n${GREEN}Fastest operation:${NC}"
printf "%-50s %6dms\n" "${TIMING_LABELS[$fastest_idx]}" "${TIMING_VALUES[$fastest_idx]}"

echo -e "\n${RED}Slowest operation:${NC}"
printf "%-50s %6dms\n" "${TIMING_LABELS[$slowest_idx]}" "${TIMING_VALUES[$slowest_idx]}"

echo -e "\n${BLUE}All timings:${NC}"
for i in $(seq 0 $((TIMING_COUNT - 1))); do
    printf "%-50s %6dms\n" "${TIMING_LABELS[$i]}" "${TIMING_VALUES[$i]}"
done | sort -k2 -n

# Calculate potential savings
echo -e "\n${MAGENTA}Performance Insights:${NC}"

# Analyze secretspec timing breakdown
if [ -f /tmp/secretspec_timing.log ]; then
    echo -e "\n${BLUE}SecretSpec Operation Breakdown:${NC}"
    grep "\[PERF\]" /tmp/secretspec_timing.log | sed 's/^/  /' || echo "  No detailed timing found"
    rm -f /tmp/secretspec_timing.log
fi

# Compare different retrieval methods
list_time=0
get_time=0
search_time=0

for i in $(seq 0 $((TIMING_COUNT - 1))); do
    case "${TIMING_LABELS[$i]}" in
        *"list items (full"*)
            list_time=${TIMING_VALUES[$i]}
            ;;
        *"get item (by name)"*)
            get_time=${TIMING_VALUES[$i]}
            ;;
        *"list --search + jq"*)
            search_time=${TIMING_VALUES[$i]}
            ;;
    esac
done

if [ $list_time -gt 0 ] && [ $get_time -gt 0 ]; then
    savings=$((list_time - get_time))
    percent=$((savings * 100 / list_time))
    echo "- Using 'bw get item' instead of 'bw list items' saves: ${savings}ms (${percent}%)"
fi

if [ $list_time -gt 0 ] && [ $search_time -gt 0 ]; then
    savings=$((list_time - search_time))
    percent=$((savings * 100 / list_time))
    echo "- Using 'bw list --search' instead of full list saves: ${savings}ms (${percent}%)"
fi

# Cleanup
echo -e "\n${YELLOW}Cleaning up...${NC}"
BW_SESSION="$BW_SESSION" bw delete item $(BW_SESSION="$BW_SESSION" bw get item "$TEST_ITEM_NAME" | jq -r '.id') --noconfirm >/dev/null 2>&1 || true
rm -f secretspec.toml

echo -e "\n${YELLOW}Performance Environment Variables:${NC}"
echo "To enable detailed timing for any SecretSpec operation:"
echo "  export SECRETSPEC_PERF_LOG=1"
echo "  secretspec get SECRET_NAME --provider bitwarden://"
echo ""
echo "This will show timing for:"
echo "  - Authentication checks"
echo "  - CLI command execution"
echo "  - JSON parsing"
echo "  - Field extraction"
echo "  - Overall operation time"

echo -e "\n${GREEN}Performance analysis complete!${NC}"