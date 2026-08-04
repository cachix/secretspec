/**
 * Cloudflare Worker entry for the docs site.
 *
 * Everything is served from the static `dist/` assets except `/api/github`,
 * which proxies the GitHub star count and latest published release. The
 * GitHub responses are cached at the
 * edge (`cf.cacheTtl`), so across all visitors we hit the GitHub API at most
 * about once per hour per data-center — comfortably under the 60 req/hr
 * unauthenticated limit — instead of once per page view.
 *
 * An optional `GITHUB_TOKEN` secret raises the upstream limit further but is
 * not required given the edge cache. Any failed value is returned as `null`
 * and its pill simply stays hidden.
 */
const REPO = "cachix/secretspec";
const TTL = 3600; // seconds

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/github") {
      return handleGitHub(env);
    }
    // Fall back to the static assets (also applies `not_found_handling`).
    return env.ASSETS.fetch(request);
  },
};

async function handleGitHub(env) {
  let stars = null;
  let release = null;
  try {
    const headers = { "User-Agent": "secretspec-docs" };
    if (env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${env.GITHUB_TOKEN}`;
    const options = {
      headers,
      // Cache GitHub's responses at the edge, shared across all visitors.
      cf: { cacheTtl: TTL, cacheEverything: true },
    };
    const [repoResponse, releaseResponse] = await Promise.all([
      fetch(`https://api.github.com/repos/${REPO}`, options),
      fetch(`https://api.github.com/repos/${REPO}/releases/latest`, options),
    ]);
    if (repoResponse.ok) {
      const data = await repoResponse.json();
      if (typeof data.stargazers_count === "number") stars = data.stargazers_count;
    }
    if (releaseResponse.ok) {
      const data = await releaseResponse.json();
      if (typeof data.tag_name === "string") release = data.tag_name;
    }
  } catch {
    // fall through with null values
  }

  return new Response(JSON.stringify({ stars, release }), {
    headers: {
      "Content-Type": "application/json",
      // Cache successes; never cache a failed lookup.
      "Cache-Control": stars !== null || release !== null ? `public, max-age=${TTL}` : "no-store",
    },
  });
}
