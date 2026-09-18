import {
  createGitHubMetadataHandler,
  createMarkdownMiddleware,
} from "@cachix/site-kit/cloudflare";

const githubMetadata = createGitHubMetadataHandler({
  repository: "cachix/secretspec",
});

// Serve the prebuilt `index.md` beside a docs page when a client prefers
// `text/markdown` over `text/html`. Browsers never ask for that, so they keep
// getting HTML, and pages without a Markdown sibling fall through to HTML.
const markdown = createMarkdownMiddleware();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/github") {
      return githubMetadata({ env });
    }
    return markdown({ request, env, next: () => env.ASSETS.fetch(request) });
  },
};
