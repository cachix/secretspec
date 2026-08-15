import { rm } from "node:fs/promises";

const cacheDirectories = ["../.astro", "../node_modules/.astro"];

await Promise.all(
  cacheDirectories.map((directory) =>
    rm(new URL(directory, import.meta.url), {
      force: true,
      recursive: true,
    }),
  ),
);
