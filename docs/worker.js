import { createGitHubMetadataHandler } from "@cachix/site-kit/cloudflare";

const githubMetadata = createGitHubMetadataHandler({
  repository: "cachix/secretspec",
});

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api/github") {
      return githubMetadata({ env });
    }
    return env.ASSETS.fetch(request);
  },
};
