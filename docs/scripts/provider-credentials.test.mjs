import assert from 'node:assert/strict';
import test from 'node:test';
import {
	compareCatalogToRust,
	extractRegisteredCredentials,
	validateCatalog,
	validateConceptPage,
	validateComponentBacklink,
	validateImplementationBacklinks,
	validateProviderPage,
	validateReferencePage,
} from './provider-credentials-lib.mjs';

function entry(overrides = {}) {
	return {
		provider: 'example',
		implementationSources: ['example.rs'],
		credentials: [
			{ name: 'token', environmentFallbacks: ['EXAMPLE_TOKEN'], since: '0.18' },
		],
		...overrides,
	};
}

test('catalog validation rejects duplicate provider and credential entries', () => {
	assert.throws(() => validateCatalog([entry(), entry()]), /duplicate provider entry/);
	assert.throws(
		() =>
			validateCatalog([
				entry({
					credentials: [
						{ name: 'token', environmentFallbacks: [], since: '0.18' },
						{ name: 'token', environmentFallbacks: [], since: '0.18' },
					],
				}),
			]),
		/duplicate credential token/,
	);
});

test('Rust registration parsing resolves constants and literal names', () => {
	const sources = new Map([
		[
			'/provider/example.rs',
			`const TOKEN: &str = "token";
crate::register_provider! {
    struct: ExampleProvider,
    config: ExampleConfig,
    name: "example",
    description: "Example {provider}",
    schemes: ["example"],
    examples: ["example://{project}"],
    credential_names: [TOKEN, "client_secret"],
}`,
		],
		['/provider/unrelated.rs', 'const TOKEN: &str = "unrelated_token";'],
	]);
	assert.deepEqual(extractRegisteredCredentials(sources).get('example'), [
		'token',
		'client_secret',
	]);
});

test('catalog comparison rejects missing, extra, renamed, and reordered credentials', () => {
	const catalog = validateCatalog([entry()]);
	assert.throws(
		() => compareCatalogToRust(catalog, new Map([['missing', ['token']]])),
		/missing from the docs catalog/,
	);
	assert.throws(
		() => compareCatalogToRust(catalog, new Map()),
		/no registered credential_names declaration/,
	);
	assert.throws(
		() => compareCatalogToRust(catalog, new Map([['example', ['renamed']]])),
		/do not match/,
	);
	const twoCredentials = validateCatalog([
		entry({
			credentials: [
				{ name: 'token', environmentFallbacks: [], since: '0.18' },
				{ name: 'secret', environmentFallbacks: [], since: '0.18' },
			],
		}),
	]);
	assert.throws(
		() => compareCatalogToRust(twoCredentials, new Map([['example', ['secret', 'token']]])),
		/do not match/,
	);
});

test('implementation backlinks require every fallback and preserve fallback order', () => {
	const catalog = [
		entry({
			credentials: [
				{
					name: 'token',
					environmentFallbacks: ['EXAMPLE_TOKEN', 'LEGACY_TOKEN'],
					since: '0.18',
				},
			],
		}),
	];
	assert.doesNotThrow(() =>
		validateImplementationBacklinks(catalog, () => 'const ENVS: &[&str] = &["EXAMPLE_TOKEN", "LEGACY_TOKEN"];'),
	);
	assert.throws(
		() => validateImplementationBacklinks(catalog, () => '["LEGACY_TOKEN", "EXAMPLE_TOKEN"]'),
		/ordered environment fallback sequence/,
	);
	assert.throws(
		() => validateImplementationBacklinks(catalog, () => '"EXAMPLE_TOKEN"'),
		/LEGACY_TOKEN is absent/,
	);
});

test('provider page checks require the standardized section and matching component', () => {
	const valid = `import ProviderCredentials from '../../../components/ProviderCredentials.astro';

## Provider credentials

<ProviderCredentials provider="example" />
`;
	assert.doesNotThrow(() => validateProviderPage('example', valid));
	assert.throws(() => validateProviderPage('example', valid.replace('## Provider credentials', '## Authentication')), /heading/);
	assert.throws(() => validateProviderPage('example', valid.replace('provider="example"', 'provider="other"')), /does not render/);
	assert.throws(() => validateProviderPage('example', valid.replace(/^import.*\n/, '')), /does not import/);
});

test('reference rendering and provider components keep their backlink contract', () => {
	const reference = `import ProviderCredentials from '../../../components/ProviderCredentials.astro';

<ProviderCredentials />
`;
	assert.doesNotThrow(() => validateReferencePage(reference));
	assert.throws(() => validateReferencePage(reference.replace('<ProviderCredentials />', '')), /complete credential catalog/);
	assert.doesNotThrow(() =>
		validateConceptPage('[provider credential reference](/reference/provider-credentials/)'),
	);
	assert.throws(() => validateConceptPage('<p>No reference link</p>'), /must link/);
	assert.doesNotThrow(() =>
		validateComponentBacklink('<a href="/reference/provider-credentials/">Provider credentials</a>'),
	);
	assert.throws(() => validateComponentBacklink('<p>No reference link</p>'), /must backlink/);
});
