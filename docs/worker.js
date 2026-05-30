/**
 * Cloudflare Worker entry for the docs site.
 *
 * Everything is served from the static `dist/` assets except `/api/stars`,
 * which proxies the GitHub star count. The GitHub response is cached at the
 * edge (`cf.cacheTtl`), so across all visitors we hit the GitHub API at most
 * about once per hour per data-center — comfortably under the 60 req/hr
 * unauthenticated limit — instead of once per page view.
 *
 * An optional `GITHUB_TOKEN` secret raises the upstream limit further but is
 * not required given the edge cache. Any failure degrades to `{ stars: null }`
 * and the pill simply stays hidden.
 */
const REPO = "cachix/secretspec";
const TTL = 3600; // seconds

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/stars") {
      return handleStars(env);
    }
    // Fall back to the static assets (also applies `not_found_handling`).
    return env.ASSETS.fetch(request);
  },
};

async function handleStars(env) {
  let stars = null;
  try {
    const headers = { "User-Agent": "secretspec-docs" };
    if (env.GITHUB_TOKEN) headers["Authorization"] = `Bearer ${env.GITHUB_TOKEN}`;
    const res = await fetch(`https://api.github.com/repos/${REPO}`, {
      headers,
      // Cache GitHub's response at the edge, shared across all visitors.
      cf: { cacheTtl: TTL, cacheEverything: true },
    });
    if (res.ok) {
      const data = await res.json();
      if (typeof data.stargazers_count === "number") stars = data.stargazers_count;
    }
  } catch {
    // fall through with stars = null
  }

  return new Response(JSON.stringify({ stars }), {
    headers: {
      "Content-Type": "application/json",
      // Cache successes; never cache a failed lookup.
      "Cache-Control": stars !== null ? `public, max-age=${TTL}` : "no-store",
    },
  });
}
