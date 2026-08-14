import assert from "node:assert/strict";
import test from "node:test";

import { extractTerminalCommands, terminalCopyPlugin } from "../src/lib/terminal-copy.mjs";

test("copies prompted commands without prompts, comments, or output", () => {
  const session = `# Set a secret
$ monosecret set DATABASE_URL --provider pass
Enter value for DATABASE_URL: ********
✓ Secret 'DATABASE_URL' saved to pass (profile: default)

# Run with secrets
$ monosecret run --provider pass -- npm start`;

  assert.equal(
    extractTerminalCommands(session),
    `monosecret set DATABASE_URL --provider pass
monosecret run --provider pass -- npm start`,
  );
});

test("joins Bash continuation lines without copying backslashes", () => {
  const session = `$ monosecret init \\
    --from 'awsps://us-east-1?template=/{profile}/{project}/{key}' \\
    --project payments \\
    --profile production
✓ Created monosecret.toml with 12 secrets`;

  assert.equal(
    extractTerminalCommands(session, "bash"),
    "monosecret init --from 'awsps://us-east-1?template=/{profile}/{project}/{key}' --project payments --profile production",
  );
  assert.equal(
    extractTerminalCommands(session, "console"),
    "monosecret init --from 'awsps://us-east-1?template=/{profile}/{project}/{key}' --project payments --profile production",
  );
});

test("preserves token boundaries across Bash continuations", () => {
  assert.equal(extractTerminalCommands("$ printf foo\\\nbar", "bash"), "printf foobar");
  assert.equal(extractTerminalCommands("$ printf foo \\\nbar", "bash"), "printf foo bar");
  assert.equal(extractTerminalCommands("$ printf foo\\\n    bar", "bash"), "printf foo bar");
});

test("preserves quoted hashes across Bash continuation lines", () => {
  const session = `$ printf "%s\\n" "hello \\
    # world"`;

  assert.equal(extractTerminalCommands(session, "bash"), 'printf "%s\\n" "hello # world"');
});

test("does not absorb continuation lines outside shell blocks", () => {
  assert.equal(extractTerminalCommands("$ command \\\n    --flag\noutput", "text"), "command \\");
});

test("omits inline annotations from copied commands", () => {
  assert.equal(
    extractTerminalCommands('$ monosecret add API_KEY --description "API access token" # 0.2+'),
    'monosecret add API_KEY --description "API access token"',
  );
  assert.equal(
    extractTerminalCommands('$ command "value # stays" https://example.test/#id'),
    'command "value # stays" https://example.test/#id',
  );
  assert.equal(extractTerminalCommands("$ command;# annotation"), "command;");
  assert.equal(extractTerminalCommands("$ printf foo\\ #bar"), "printf foo\\ #bar");
});

test("leaves command-only blocks unchanged", () => {
  assert.equal(extractTerminalCommands("npm install\nnpm test"), "npm install\nnpm test");
});

function terminalBlockAst(lineCount, isTerminal = true) {
  const button = {
    type: "element",
    tagName: "button",
    properties: { dataCode: "$ monosecret check\u007f✓ All secrets are set" },
    children: [{ type: "element", tagName: "div", properties: {}, children: [] }],
  };
  const blockAst = {
    type: "element",
    tagName: "figure",
    properties: {
      className: isTerminal ? ["frame", "is-terminal"] : ["frame"],
    },
    children: [
      {
        type: "element",
        tagName: "pre",
        properties: {},
        children: [
          {
            type: "element",
            tagName: "code",
            properties: {},
            children: Array.from({ length: lineCount }, () => ({
              type: "element",
              tagName: "div",
              properties: { className: ["ec-line"] },
              children: [],
            })),
          },
        ],
      },
      {
        type: "element",
        tagName: "div",
        properties: { className: ["copy"] },
        children: [button],
      },
    ],
  };

  return { blockAst, button };
}

test("renders one copy button beside each prompted command", () => {
  const { blockAst } = terminalBlockAst(5);

  terminalCopyPlugin().hooks.postprocessRenderedBlock({
    codeBlock: {
      language: "console",
      code: `# Check secrets
$ monosecret check
✓ All secrets are set

$ monosecret run -- npm start`,
    },
    renderData: { blockAst },
  });

  const lines = blockAst.children[0].children[0].children;
  assert.deepEqual(
    lines.map((line) => line.properties.className),
    [
      ["ec-line"],
      ["ec-line", "terminal-command-start"],
      ["ec-line"],
      ["ec-line"],
      ["ec-line", "terminal-command-start"],
    ],
  );
  assert.equal(lines[1].children[0].properties.className[0], "copy");
  assert.equal(lines[1].children[0].children[0].properties.dataCode, "monosecret check");
  assert.equal(lines[4].children[0].children[0].properties.dataCode, "monosecret run -- npm start");
  assert.equal(
    blockAst.children.some((child) => child === lines[1].children[0]),
    false,
  );
  assert.equal(
    blockAst.children.some((child) => child.properties?.className?.includes("copy")),
    false,
  );
});

test("renders one copy button for a multiline prompted command", () => {
  const { blockAst } = terminalBlockAst(4);

  terminalCopyPlugin().hooks.postprocessRenderedBlock({
    codeBlock: {
      language: "bash",
      code: `$ monosecret init \\
    --project payments \\
    --profile production
✓ Created monosecret.toml`,
    },
    renderData: { blockAst },
  });

  const lines = blockAst.children[0].children[0].children;
  assert.equal(lines[0].children.length, 1);
  assert.equal(lines[1].children.length, 0);
  assert.equal(lines[2].children.length, 0);
  assert.equal(
    lines[0].children[0].children[0].properties.dataCode,
    "monosecret init --project payments --profile production",
  );
});

test("leaves command-only shell blocks on the default copy button", () => {
  const { blockAst } = terminalBlockAst(1);

  terminalCopyPlugin().hooks.postprocessRenderedBlock({
    codeBlock: { language: "bash", code: "monosecret-update" },
    renderData: { blockAst },
  });

  const line = blockAst.children[0].children[0].children[0];
  assert.deepEqual(line.properties.className, ["ec-line"]);
  assert.equal(line.children.length, 0);
  assert.equal(blockAst.children[1].properties.className[0], "copy");
});

test("supports prompted terminal languages outside the continuation allowlist", () => {
  const { blockAst } = terminalBlockAst(2);

  terminalCopyPlugin().hooks.postprocessRenderedBlock({
    codeBlock: { language: "zsh", code: "$ monosecret check\noutput" },
    renderData: { blockAst },
  });

  const line = blockAst.children[0].children[0].children[0];
  assert.equal(line.children[0].properties.className[1], "terminal-line-copy");
  assert.equal(line.children[0].children[0].properties.dataCode, "monosecret check");
});

test("cleans prompted blocks even when their frame is nonterminal", () => {
  const { blockAst } = terminalBlockAst(1, false);

  terminalCopyPlugin().hooks.postprocessRenderedBlock({
    codeBlock: { language: "bash", code: "$ monosecret check" },
    renderData: { blockAst },
  });

  const line = blockAst.children[0].children[0].children[0];
  assert.equal(line.children[0].properties.className[1], "terminal-line-copy");
  assert.equal(line.children[0].children[0].properties.dataCode, "monosecret check");
  assert.equal(blockAst.children.length, 1);
});

test("does not add a copy button for an empty prompted annotation", () => {
  const { blockAst } = terminalBlockAst(1);

  terminalCopyPlugin().hooks.postprocessRenderedBlock({
    codeBlock: { language: "bash", code: "$ # 0.2+" },
    renderData: { blockAst },
  });

  const line = blockAst.children[0].children[0].children[0];
  assert.equal(line.children.length, 0);
  assert.equal(blockAst.children.length, 1);
});

test("keeps the default button when replacement AST validation fails", () => {
  const { blockAst } = terminalBlockAst(1);
  blockAst.children[1].children = [];

  terminalCopyPlugin().hooks.postprocessRenderedBlock({
    codeBlock: { language: "bash", code: "$ monosecret check" },
    renderData: { blockAst },
  });

  assert.equal(blockAst.children.length, 2);
  assert.equal(blockAst.children[1].properties.className[0], "copy");
});
