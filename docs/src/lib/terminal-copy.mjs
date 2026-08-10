function scanShellLine(line, initialQuote) {
  let quote = initialQuote;
  let escaped = false;

  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (character === "\\" && quote !== "'") {
      escaped = true;
      continue;
    }
    if ((character === "'" || character === '"') && !quote) {
      quote = character;
      continue;
    }
    if (character === quote) {
      quote = undefined;
      continue;
    }
    if (
      character === "#" &&
      !quote &&
      (index === 0 || /\s/.test(line[index - 1]))
    ) {
      return {
        text: line.slice(0, index).trimEnd(),
        quote,
        escaped: false,
      };
    }
  }

  return { text: line, quote, escaped };
}

function withoutLineContinuation(line) {
  return line.trimEnd().slice(0, -1).trimEnd();
}

export function extractTerminalCommandGroups(code, language = "bash") {
  const lines = code.split("\n");
  const commands = [];
  let current;
  const supportsContinuation = ["bash", "console", "sh", "shell"].includes(
    language,
  );

  for (const [lineIndex, line] of lines.entries()) {
    const prompted = line.match(/^\s*\$\s(.*)$/);
    if (prompted) {
      const scanned = scanShellLine(prompted[1]);
      const continues = supportsContinuation && scanned.escaped;
      current = {
        lineIndex,
        lines: [
          continues ? withoutLineContinuation(scanned.text) : scanned.text,
        ],
        quote: scanned.quote,
      };
      commands.push(current);
      if (!continues) current = undefined;
      continue;
    }

    if (current) {
      const scanned = scanShellLine(line, current.quote);
      const continues = scanned.escaped;
      current.lines.push(
        (continues
          ? withoutLineContinuation(scanned.text)
          : scanned.text
        ).trim(),
      );
      current.quote = scanned.quote;
      if (!continues) current = undefined;
    }
  }

  return commands
    .map(({ lineIndex, lines: commandLines }) => ({
      lineIndex,
      command: commandLines.join(" ").trim(),
    }))
    .filter(({ command }) => command.length > 0);
}

export function extractTerminalCommands(code, language = "bash") {
  const commands = extractTerminalCommandGroups(code, language);
  return commands.length
    ? commands.map(({ command }) => command).join("\n")
    : code;
}

function findElement(node, predicate, parent) {
  if (!node || node.type !== "element") return undefined;
  if (predicate(node)) return { node, parent };

  for (const child of node.children ?? []) {
    const result = findElement(child, predicate, node);
    if (result) return result;
  }

  return undefined;
}

function hasClass(node, className) {
  return node.properties?.className?.includes(className);
}

function cloneNode(node) {
  return {
    ...node,
    properties: { ...node.properties },
    children: node.children?.map(cloneNode) ?? [],
  };
}

export function terminalCopyPlugin() {
  return {
    name: "SecretSpec terminal copy",
    hooks: {
      postprocessRenderedBlock: ({ codeBlock, renderData }) => {
        if (!hasClass(renderData.blockAst, "is-terminal")) return;
        const commands = extractTerminalCommandGroups(
          codeBlock.code,
          codeBlock.language,
        );
        if (!commands.length) return;

        const copy = findElement(renderData.blockAst, (node) =>
          hasClass(node, "copy"),
        );
        const code = findElement(
          renderData.blockAst,
          (node) => node.tagName === "code",
        );
        if (!copy?.parent || !code) return;

        const copyIndex = copy.parent.children.indexOf(copy.node);
        copy.parent.children.splice(copyIndex, 1);

        for (const { lineIndex, command } of commands) {
          const line = code.node.children[lineIndex];
          if (!line) continue;

          const lineCopy = cloneNode(copy.node);
          lineCopy.properties.className = ["copy", "terminal-line-copy"];
          const button = findElement(
            lineCopy,
            (node) => node.tagName === "button",
          )?.node;
          if (!button) continue;

          if ("dataCode" in button.properties) {
            button.properties.dataCode = command;
          } else {
            button.properties["data-code"] = command;
          }

          line.properties.className = [
            ...(line.properties.className ?? []),
            "terminal-command-start",
          ];
          line.children.push(lineCopy);
        }
      },
    },
  };
}
