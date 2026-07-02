#!/usr/bin/env bash
set -euo pipefail

token="${RELEASE_PR_MERGE_TOKEN:-}"

validate_token() {
	GH_TOKEN="$token" gh api user --jq '{id: .id, login: .login, name: .name}'
}

if [ -z "$token" ]; then
	echo "::error::RELEASE_PR_MERGE_TOKEN was not loaded from Monosecret." >&2
	exit 1
fi

if ! user_info="$(validate_token)"; then
	echo "::error::Monosecret-loaded RELEASE_PR_MERGE_TOKEN is not valid for GitHub." >&2
	exit 1
fi

user_id="$(echo "$user_info" | jq -r '.id')"
user_login="$(echo "$user_info" | jq -r '.login')"
user_name="$(echo "$user_info" | jq -r '.name // .login')"
credential="$(printf 'x-access-token:%s' "$token" | base64 | tr -d '\n')"

git config user.name "$user_name"
git config user.email "${user_id}+${user_login}@users.noreply.github.com"
git config --local http.https://github.com/.extraheader "AUTHORIZATION: basic ${credential}"
