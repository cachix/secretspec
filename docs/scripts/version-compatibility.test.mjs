import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, extname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { preserveHeadingIdPlugin } from '../src/lib/preserve-heading-id.mjs';

const docsRoot = fileURLToPath(new URL('../src/content/docs/', import.meta.url));

function documentationFiles(directory) {
	return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
		const path = join(directory, entry.name);
		if (entry.isDirectory()) return documentationFiles(path);
		return ['.md', '.mdx'].includes(extname(entry.name)) ? [path] : [];
	});
}

const files = documentationFiles(docsRoot);

function withoutCodeFences(source) {
	return source.replace(/^[ \t]*```[^\n]*\n[\s\S]*?^[ \t]*```[ \t]*$/gm, '');
}

test('version notices use the shared component', () => {
	const legacyPatterns = [
		/:::(?:note|caution)\[Version compatibility\]/,
		/> \*\*Version compatibility:\*\*/,
	];

	for (const path of files) {
		const source = withoutCodeFences(readFileSync(path, 'utf8'));
		for (const pattern of legacyPatterns) {
			assert.doesNotMatch(source, pattern, `${path} uses a legacy version notice`);
		}
	}
});

test('component users are MDX files with one resolvable import', () => {
	let notices = 0;

	for (const path of files) {
		const source = withoutCodeFences(readFileSync(path, 'utf8'));
		const openings = source.match(/<VersionCompatibility(?:\s[^>]*)?\s*\/?>/g) ?? [];
		if (openings.length === 0) continue;

		notices += openings.length;
		assert.equal(extname(path), '.mdx', `${path} must use the .mdx extension`);

		const imports = [
			...source.matchAll(
				/import VersionCompatibility from ['"]([^'"]+VersionCompatibility\.astro)['"];?/g,
			),
		];
		assert.equal(imports.length, 1, `${path} must import VersionCompatibility exactly once`);
		assert.ok(
			existsSync(resolve(dirname(path), imports[0][1])),
			`${path} has an invalid VersionCompatibility import`,
		);
		for (const opening of openings) {
			assert.match(
				opening,
				/\sversion="0\.\d+"/,
				`${path} must give every VersionCompatibility notice a version`,
			);
			const changed = opening.includes('kind="changed"');
			const selfClosing = opening.endsWith('/>');
			assert.equal(
				selfClosing,
				!changed,
				`${path} must keep new notices bodyless and give changed notices a body`,
			);
		}
		const expandedOpenings = openings.filter((opening) => !opening.endsWith('/>'));
		assert.equal(
			expandedOpenings.length,
			(source.match(/<\/VersionCompatibility>/g) ?? []).length,
			`${path} has an unclosed VersionCompatibility component`,
		);

		const firstNotice = source.search(/<VersionCompatibility/);
		const firstSection = source.search(/^## /m);
		if (firstNotice >= 0 && (firstSection < 0 || firstNotice < firstSection)) {
			const contentBeforeNotice = source
				.slice(0, firstNotice)
				.replace(/^---\n[\s\S]*?\n---\n/, '')
				.replace(/^import .*;\s*$/gm, '')
				.trim();
			assert.equal(
				contentBeforeNotice,
				'',
				`${path} must put its page-level version notice at the very top`,
			);
		}
	}

	assert.ok(notices > 0, 'expected documentation to contain version notices');
});

test('versioned headings keep their historical URL and put the notice below the heading', () => {
	let versionedHeadings = 0;
	const markerPattern = /^(#{2,6}) (.*?) \{\/\* #([A-Za-z][\w:.-]*) \*\/\}$/gm;
	const versionInTitle = /\(0\.\d+\+\)|\bSecretSpec 0\.\d+\b|\bstored by 0\.\d+\b/i;

	for (const path of files) {
		const source = withoutCodeFences(readFileSync(path, 'utf8'));
		const headingIds = new Set();
		for (const match of source.matchAll(markerPattern)) {
			versionedHeadings += 1;
			assert.doesNotMatch(match[2], versionInTitle, `${path} exposes a version in a heading`);
			assert.ok(!headingIds.has(match[3]), `${path} repeats heading ID ${match[3]}`);
			headingIds.add(match[3]);

			const nextContent = source.slice(match.index + match[0].length).trimStart();
			assert.match(
				nextContent,
				/^<VersionCompatibility\s/,
				`${path} must put a version notice immediately below ${match[2]}`,
			);
		}
	}

	assert.ok(versionedHeadings > 0, 'expected documentation to contain versioned headings');
});

test('historical heading IDs are applied without entering the rendered title', () => {
	const marker = { type: 'mdxTextExpression', value: '/* #feature-name-020 */' };
	const heading = {
		type: 'heading',
		depth: 2,
		children: [{ type: 'text', value: 'Feature name ' }, marker],
	};
	const tree = { type: 'root', children: [heading] };

	preserveHeadingIdPlugin()(tree);

	assert.deepEqual(heading.children, [{ type: 'text', value: 'Feature name' }]);
	assert.equal(heading.data.hProperties.id, 'feature-name-020');
});
