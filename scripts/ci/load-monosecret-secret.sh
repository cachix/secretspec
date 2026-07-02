#!/usr/bin/env bash
set -euo pipefail

secret_name="${1:?usage: load-monosecret-secret.sh SECRET_NAME}"
profile="${MONOSECRET_PROFILE:-ci}"
reason="${MONOSECRET_REASON:-${MONOSECRET_LOAD_REASON:-GitHub Actions loading ${secret_name}}}"
fallback_var="FALLBACK_${secret_name}"
fallback_value="${!fallback_var:-}"
optional="${MONOSECRET_LOAD_OPTIONAL:-false}"

write_github_env() {
	local name="$1"
	local value="$2"
	local delimiter="__MONOSECRET_${name}__"

	echo "::add-mask::$value"
	{
		echo "${name}<<${delimiter}"
		printf '%s\n' "$value"
		echo "$delimiter"
	} >>"$GITHUB_ENV"
}

if [ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]; then
	cargo run -p monosecret -- --reason "$reason" run --profile "$profile" --include "$secret_name" -- bash -c '
    set -euo pipefail
    secret_name="$1"
    value="${!secret_name}"
    delimiter="__MONOSECRET_${secret_name}__"

    echo "::add-mask::$value"
    {
      echo "${secret_name}<<${delimiter}"
      printf "%s\n" "$value"
      echo "$delimiter"
    } >> "$GITHUB_ENV"
  ' bash "$secret_name"
	exit 0
fi

if [ -n "$fallback_value" ]; then
	echo "::notice::OP_SERVICE_ACCOUNT_TOKEN is not configured; using fallback GitHub secret for ${secret_name}."
	write_github_env "$secret_name" "$fallback_value"
	exit 0
fi

if [ "$optional" = "true" ]; then
	echo "::notice::No Monosecret bootstrap token or fallback value found for optional secret ${secret_name}."
	exit 0
fi

echo "::error::Unable to load ${secret_name}. Configure OP_SERVICE_ACCOUNT_TOKEN or provide ${fallback_var}." >&2
exit 1
