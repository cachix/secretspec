import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import test from 'node:test';

import { checkInternalLinks } from './check-internal-links.mjs';

async function writeSite(t, files) {
  const container = await mkdtemp(join(tmpdir(), 'secretspec-links-'));
  const root = join(container, 'dist');
  t.after(() => rm(container, { recursive: true, force: true }));

  await Promise.all(
    Object.entries(files).map(async ([path, contents]) => {
      const destination = join(root, path);
      await mkdir(dirname(destination), { recursive: true });
      await writeFile(destination, contents);
    }),
  );

  return root;
}

test('accepts existing pages, files, and fragments', async (t) => {
  const root = await writeSite(t, {
    'index.html': `
      <link rel="canonical" href="https://secretspec.dev/generated-canonical/">
      <main id="home">
        <a href="#home">Home</a>
        <a href="/guide/">Guide</a>
        <a href="/guide/#details">Details</a>
        <a href="/guide/?mode=short#details">Details with query</a>
        <a href="/feed.xml">Feed</a>
        <a href="https://example.com/">External</a>
        <a href="mailto:team@example.com">Email</a>
      </main>
    `,
    'guide/index.html': '<h1 id="details">Details</h1><a href="../">Home</a>',
    'feed.xml': '<feed />',
  });

  assert.deepEqual(await checkInternalLinks(root), []);
});

test('reports missing pages and fragments with their source', async (t) => {
  const root = await writeSite(t, {
    'index.html': `
      <meta name="metadata-only">
      <a href="/missing/">Missing page</a>
      <a href="/guide/#absent">Missing fragment</a>
      <a href="/guide#also-absent">Missing fragment without trailing slash</a>
      <a href="https://secretspec.dev/also-missing/">Missing absolute page</a>
      <a href="#metadata-only">Metadata is not an anchor</a>
    `,
    'guide/index.html': '<h1 id="present">Guide</h1>',
  });

  assert.deepEqual(await checkInternalLinks(root), [
    {
      source: 'index.html',
      href: '/missing/',
      reason: 'target does not exist',
    },
    {
      source: 'index.html',
      href: '/guide/#absent',
      reason: 'fragment #absent does not exist',
    },
    {
      source: 'index.html',
      href: '/guide#also-absent',
      reason: 'fragment #also-absent does not exist',
    },
    {
      source: 'index.html',
      href: 'https://secretspec.dev/also-missing/',
      reason: 'target does not exist',
    },
    {
      source: 'index.html',
      href: '#metadata-only',
      reason: 'fragment #metadata-only does not exist',
    },
  ]);
});

test('rejects encoded targets outside the generated site', async (t) => {
  const root = await writeSite(t, {
    'index.html': '<a href="/%2e%2e%2foutside.html#present">Outside</a>',
  });
  await writeFile(join(dirname(root), 'outside.html'), '<h1 id="present">Outside</h1>');

  assert.deepEqual(await checkInternalLinks(root), [
    {
      source: 'index.html',
      href: '/%2e%2e%2foutside.html#present',
      reason: 'target does not exist',
    },
  ]);
});

test('matches href, id, and name as exact attribute names', async (t) => {
  const root = await writeSite(t, {
    'index.html': `
      <div data-id="not-an-id"></div>
      <script>
        const example = '<h2 id="script-only"></h2><a href="/script-only/">Script</a>';
        const commentStart = '<!--';
      </script>
      <!-- A real comment after the script must not change script parsing. -->
      <!-- <h2 id="comment-only"></h2><a href="/comment-only/">Comment</a> -->
      <a data-href="/missing/">Data only</a>
      <a href="#not-an-id">Missing fragment</a>
      <a href="#script-only">Script text is not an anchor</a>
      <a href="#comment-only">Comment text is not an anchor</a>
    `,
  });

  assert.deepEqual(await checkInternalLinks(root), [
    {
      source: 'index.html',
      href: '#not-an-id',
      reason: 'fragment #not-an-id does not exist',
    },
    {
      source: 'index.html',
      href: '#script-only',
      reason: 'fragment #script-only does not exist',
    },
    {
      source: 'index.html',
      href: '#comment-only',
      reason: 'fragment #comment-only does not exist',
    },
  ]);
});
