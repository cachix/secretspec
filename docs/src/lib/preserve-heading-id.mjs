const explicitHeadingId = /^\s*\/\*\s*#([A-Za-z][\w:.-]*)\s*\*\/\s*$/;

/**
 * Preserve a historical heading URL while allowing its visible title to change.
 *
 * Usage: `## Clean title {/* #historical-heading-id *\/}`
 */
export function preserveHeadingIdPlugin() {
  return (tree) => {
    walk(tree, (node) => {
      if (node.type !== "heading") return;

      const marker = node.children.at(-1);
      if (marker?.type !== "mdxTextExpression") return;

      const match = explicitHeadingId.exec(marker.value);
      if (!match) return;

      node.children.pop();
      const titleEnd = node.children.at(-1);
      if (titleEnd?.type === "text") titleEnd.value = titleEnd.value.trimEnd();
      node.data ??= {};
      node.data.hProperties ??= {};
      node.data.hProperties.id = match[1];
    });
  };
}

function walk(node, visit) {
  visit(node);
  if (!Array.isArray(node.children)) return;
  for (const child of node.children) walk(child, visit);
}
