import { realpathSync, statSync } from 'node:fs';
import { readFile, readdir } from 'node:fs/promises';
import { isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const SITE_ORIGIN = 'https://secretspec.internal';
const INTERNAL_ORIGINS = new Set([SITE_ORIGIN, 'https://secretspec.dev']);

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = await Promise.all(
    entries.map(async (entry) => {
      const path = join(directory, entry.name);
      return entry.isDirectory() ? listFiles(path) : [path];
    }),
  );

  return files.flat().sort();
}

function decodeHtml(value) {
  return value.replace(
    /&(?:amp|quot|apos|#39|#x27);/gi,
    (entity) =>
      ({
        '&amp;': '&',
        '&quot;': '"',
        '&apos;': "'",
        '&#39;': "'",
        '&#x27;': "'",
      })[entity.toLowerCase()],
  );
}

function stripIgnoredMarkup(html) {
  return html
    .replace(/<(script|style|template)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, '')
    .replace(/<!--[\s\S]*?-->/g, '');
}

function pagePath(root, source) {
  const path = relative(root, source).split(sep).join('/');
  if (path === 'index.html') return '/';
  if (path.endsWith('/index.html')) return `/${path.slice(0, -'index.html'.length)}`;
  return `/${path}`;
}

function isInside(root, path) {
  const pathFromRoot = relative(root, path);
  return (
    pathFromRoot === '' ||
    (pathFromRoot !== '..' &&
      !pathFromRoot.startsWith(`..${sep}`) &&
      !isAbsolute(pathFromRoot))
  );
}

function resolveTarget(root, realRoot, pathname) {
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(pathname);
  } catch {
    return undefined;
  }

  const relativePath = decodedPath.replace(/^\/+/, '');
  const base = resolve(root, relativePath);
  if (!isInside(root, base)) return undefined;

  const candidates = decodedPath.endsWith('/')
    ? [join(base, 'index.html')]
    : [base, `${base}.html`, join(base, 'index.html')];

  return candidates.find((candidate) => {
    try {
      return statSync(candidate).isFile() && isInside(realRoot, realpathSync(candidate));
    } catch {
      return false;
    }
  });
}

function extractAttributes(html, attribute) {
  const values = [];
  const pattern = new RegExp(`(?:^|\\s)${attribute}\\s*=\\s*(["'])(.*?)\\1`, 'gis');
  for (const match of html.matchAll(pattern)) values.push(decodeHtml(match[2]));
  return values;
}

function extractElementAttributes(html, attribute) {
  return [...html.matchAll(/<[a-z][^>]*>/gis)].flatMap(([tag]) =>
    extractAttributes(tag, attribute),
  );
}

function extractAnchorAttributes(html, attribute) {
  return [...html.matchAll(/<a\b[^>]*>/gis)].flatMap(([tag]) =>
    extractAttributes(tag, attribute),
  );
}

export async function checkInternalLinks(rootDirectory) {
  const root = resolve(rootDirectory);
  const realRoot = realpathSync(root);
  const sources = (await listFiles(root)).filter((path) => path.endsWith('.html'));
  const htmlCache = new Map();
  const anchorCache = new Map();
  const issues = [];

  async function readHtml(path) {
    if (!htmlCache.has(path)) htmlCache.set(path, await readFile(path, 'utf8'));
    return htmlCache.get(path);
  }

  async function anchorsFor(path) {
    if (!anchorCache.has(path)) {
      const html = stripIgnoredMarkup(await readHtml(path));
      anchorCache.set(
        path,
        new Set([
          ...extractElementAttributes(html, 'id'),
          ...extractAnchorAttributes(html, 'name'),
        ]),
      );
    }
    return anchorCache.get(path);
  }

  for (const source of sources) {
    const html = stripIgnoredMarkup(await readHtml(source));
    const sourceName = relative(root, source).split(sep).join('/');
    const base = new URL(pagePath(root, source), SITE_ORIGIN);

    for (const href of extractAnchorAttributes(html, 'href')) {
      let url;
      try {
        url = new URL(href, base);
      } catch {
        continue;
      }

      if (!INTERNAL_ORIGINS.has(url.origin)) continue;

      const target = resolveTarget(root, realRoot, url.pathname);
      if (!target) {
        issues.push({ source: sourceName, href, reason: 'target does not exist' });
        continue;
      }

      if (url.hash && target.endsWith('.html')) {
        let fragment;
        try {
          fragment = decodeURIComponent(url.hash.slice(1));
        } catch {
          fragment = url.hash.slice(1);
        }

        if (fragment && !(await anchorsFor(target)).has(fragment)) {
          issues.push({
            source: sourceName,
            href,
            reason: `fragment #${fragment} does not exist`,
          });
        }
      }
    }
  }

  return issues;
}

const invokedPath = process.argv[1] && resolve(process.argv[1]);
if (invokedPath === fileURLToPath(import.meta.url)) {
  const root = resolve(process.argv[2] ?? 'dist');
  const issues = await checkInternalLinks(root);

  if (issues.length > 0) {
    for (const issue of issues) {
      console.error(`${issue.source}: ${issue.href} (${issue.reason})`);
    }
    console.error(`Found ${issues.length} broken internal link${issues.length === 1 ? '' : 's'}.`);
    process.exitCode = 1;
  } else {
    console.log('Internal links are valid.');
  }
}
