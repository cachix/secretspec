import { existsSync, readFileSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { Monosecret } from "../src/index.js";

const packageDirectory = dirname(dirname(fileURLToPath(import.meta.url)));
const repository = join(packageDirectory, "..", "..");
const fixtures = join(repository, "conformance", "fixtures");
const nativeBuilt = existsSync(join(packageDirectory, "monosecret-client.node"));

describe.skipIf(!nativeBuilt)("embedded native resolver", () => {
  it("matches every shared conformance fixture", async () => {
    for (const fixture of await readdir(fixtures)) {
      const directory = join(fixtures, fixture);
      const expected = JSON.parse(readFileSync(join(directory, "expected.json"), "utf8")) as {
        profile: string;
        secrets: Record<string, { value: string; source: string; as_path: boolean }>;
        missing_required: string[];
        missing_optional: string[];
      };
      const resolved = await Monosecret.builder()
        .withPath(join(directory, "monosecret.toml"))
        .withProvider(`dotenv://${join(directory, ".env")}`)
        .withReason("conformance")
        .loadAsync();

      try {
        expect({
          profile: resolved.profile,
          secrets: Object.fromEntries(
            Object.entries(resolved.secrets).map(([name, secret]) => [
              name,
              {
                value:
                  secret.asPath && secret.path !== null
                    ? readFileSync(secret.path, "utf8")
                    : secret.get(),
                source: secret.source,
                as_path: secret.asPath,
              },
            ]),
          ),
          missing_required: [],
          missing_optional: resolved.missingOptional,
        }).toEqual(expected);
      } finally {
        resolved.dispose();
      }
    }
  });
});
