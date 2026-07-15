<?php

declare(strict_types=1);

namespace Secretspec\Tests;

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Secretspec\Builder;
use Secretspec\Report;
use Secretspec\Resolved;
use Secretspec\SecretSpec;

/**
 * Cross-language conformance: resolve the shared fixtures and assert this SDK
 * produces the canonical result every other SDK must also produce.
 */
final class ConformanceTest extends TestCase
{
    private const FIXTURES = __DIR__ . '/../../conformance/fixtures';

    /** @return iterable<string, array{0: string}> */
    public static function fixtures(): iterable
    {
        foreach (\glob(self::FIXTURES . '/*', \GLOB_ONLYDIR) ?: [] as $dir) {
            yield \basename($dir) => [$dir];
        }
    }

    #[DataProvider('fixtures')]
    public function testConformance(string $dir): void
    {
        $expected = self::readJson($dir . '/expected.json');
        // Close the Resolved so as_path temp files do not accumulate.
        $resolved = $this->builder($dir)->load();
        try {
            self::assertEquals($expected, $this->canonical($resolved));
        } finally {
            $resolved->close();
        }
    }

    /**
     * Under no_values every SDK must emit the same all-null fields map: a
     * value-less secret serializes to null, not an empty string.
     */
    #[DataProvider('fixtures')]
    public function testConformanceNoValues(string $dir): void
    {
        $expected = self::readJson($dir . '/expected_no_values.json');
        $resolved = $this->builder($dir)->withNoValues()->load();
        self::assertEquals($expected, $resolved->fields());
    }

    /** The value-free report (status + provenance) is identical across SDKs. */
    #[DataProvider('fixtures')]
    public function testConformanceReport(string $dir): void
    {
        $expected = self::readJson($dir . '/expected_report.json');
        self::assertEquals($expected, $this->canonicalReport($this->builder($dir)->report()));
    }

    private function builder(string $dir): Builder
    {
        return SecretSpec::builder()
            ->withPath($dir . '/secretspec.toml')
            ->withProvider('dotenv://' . $dir . '/.env')
            ->withReason('conformance');
    }

    /** @return array<string, mixed> */
    private function canonical(Resolved $resolved): array
    {
        $secrets = [];
        foreach ($resolved->secrets as $name => $secret) {
            $value = $secret->asPath ? \file_get_contents($secret->get()) : $secret->value;
            $secrets[$name] = ['value' => $value, 'source' => $secret->source, 'as_path' => $secret->asPath];
        }
        $missingOptional = $resolved->missingOptional;
        \sort($missingOptional);

        return [
            'profile' => $resolved->profile,
            'secrets' => $secrets,
            'missing_required' => [],
            'missing_optional' => $missingOptional,
        ];
    }

    /** @return array<string, mixed> */
    private function canonicalReport(Report $report): array
    {
        $secrets = [];
        foreach ($report->secrets as $s) {
            $secrets[$s->name] = [
                'status' => $s->status,
                'required' => $s->required,
                'as_path' => $s->asPath,
                'generated' => $s->generated,
                'default_applied' => $s->defaultApplied,
                // Present-or-not (not the path-dependent value) so the vector is
                // machine-independent yet still catches a dropped source_provider.
                'source_provider' => $s->sourceProvider !== null,
            ];
        }

        return ['profile' => $report->profile, 'secrets' => $secrets];
    }

    /** @return array<string, mixed> */
    private static function readJson(string $path): array
    {
        return \json_decode((string) \file_get_contents($path), true, 512, \JSON_THROW_ON_ERROR);
    }
}
