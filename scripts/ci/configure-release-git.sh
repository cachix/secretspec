#!/usr/bin/env bash
set -euo pipefail

primary_token="${RELEASE_PR_MERGE_TOKEN:-}"
fallback_token="${FALLBACK_RELEASE_PR_MERGE_TOKEN:-}"

validate_token() {
	local token="$1"
	GH_TOKEN="$token" gh api user --jq '{id: .id, login: .login, name: .name}'
}

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

if [ -z "$primary_token" ]; then
	echo "::error::RELEASE_PR_MERGE_TOKEN was not loaded." >&2
	exit 1
fi

if user_info="$(validate_token "$primary_token")"; then
	token="$primary_token"
elif [ -n "$fallback_token" ] && [ "$fallback_token" != "$primary_token" ]; then
	echo "::notice::Loaded RELEASE_PR_MERGE_TOKEN is not valid for GitHub; using fallback GitHub secret."
	user_info="$(validate_token "$fallback_token")"
	token="$fallback_token"
	write_github_env RELEASE_PR_MERGE_TOKEN "$token"
else
	echo "::error::Loaded RELEASE_PR_MERGE_TOKEN is not valid for GitHub and no fallback is available." >&2
	exit 1
fi

user_id="$(echo "$user_info" | jq -r '.id')"
user_login="$(echo "$user_info" | jq -r '.login')"
user_name="$(echo "$user_info" | jq -r '.name // .login')"
credential="$(printf 'x-access-token:%s' "$token" | base64 | tr -d '\n')"

git config user.name "$user_name"
git config user.email "${user_id}+${user_login}@users.noreply.github.com"
git config --local http.https://github.com/.extraheader "AUTHORIZATION: basic ${credential}"
