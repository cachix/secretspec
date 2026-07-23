<?php

declare(strict_types=1);

namespace Secretspec\Tests;

use PHPUnit\Framework\TestCase;
use Secretspec\MissingRequiredException;
use Secretspec\SecretReport;
use Secretspec\SecretSpec;
use Secretspec\SecretSpecException;

final class ResolveTest extends TestCase
{
    private const MANIFEST = <<<'TOML'
        [project]
        name = "php-test"
        revision = "1.0"

        [profiles.default]
        DATABASE_URL = { description = "DB", required = true }
        LOG_LEVEL = { description = "log", required = false, default = "info" }
        SENTRY_DSN = { description = "sentry", required = false }

        [scopes.database]
        secrets = ["DATABASE_URL"]
        TOML;

    /** @var list<string> directories to remove after each test */
    private array $tmpDirs = [];

    protected function tearDown(): void
    {
        foreach ($this->tmpDirs as $dir) {
            self::removeDir($dir);
        }
        $this->tmpDirs = [];
    }

    /**
     * Write a manifest + `.env` into a fresh temp dir.
     *
     * @return array{0: string, 1: string} the manifest path and a `dotenv://` provider
     */
    private function project(string $dotenv, string $manifest = self::MANIFEST): array
    {
        $dir = \sys_get_temp_dir() . \DIRECTORY_SEPARATOR . 'secretspec-php-' . \bin2hex(\random_bytes(8));
        \mkdir($dir);
        $this->tmpDirs[] = $dir;

        $manifestPath = $dir . \DIRECTORY_SEPARATOR . 'secretspec.toml';
        $envPath = $dir . \DIRECTORY_SEPARATOR . '.env';
        \file_put_contents($manifestPath, $manifest);
        \file_put_contents($envPath, $dotenv);

        return [$manifestPath, 'dotenv://' . $envPath];
    }

    public function testAbiVersionNonEmpty(): void
    {
        self::assertNotEmpty(SecretSpec::abiVersion());
    }

    public function testLoadValuesAndProvenance(): void
    {
        [$manifest, $provider] = $this->project("DATABASE_URL=postgres://db\n");

        $resolved = SecretSpec::builder()
            ->withPath($manifest)
            ->withProvider($provider)
            ->withReason('php test')
            ->load();

        self::assertSame('default', $resolved->profile);

        $db = $resolved->secrets['DATABASE_URL'];
        self::assertSame('postgres://db', $db->get());
        self::assertSame('provider', $db->source);
        self::assertNotNull($db->sourceProvider);

        $log = $resolved->secrets['LOG_LEVEL'];
        self::assertSame('info', $log->get());
        self::assertSame('default', $log->source);

        self::assertSame(['SENTRY_DSN'], $resolved->missingOptional);
        self::assertArrayNotHasKey('SENTRY_DSN', $resolved->secrets);
    }

    public function testSetAsEnv(): void
    {
        [$manifest, $provider] = $this->project("DATABASE_URL=postgres://db\n");
        \putenv('DATABASE_URL');
        unset($_ENV['DATABASE_URL'], $_SERVER['DATABASE_URL']);

        SecretSpec::builder()
            ->withPath($manifest)
            ->withProvider($provider)
            ->withReason('php test')
            ->load()
            ->setAsEnv();

        self::assertSame('postgres://db', \getenv('DATABASE_URL'));
        self::assertSame('postgres://db', $_ENV['DATABASE_URL']);

        \putenv('DATABASE_URL');
        unset($_ENV['DATABASE_URL'], $_SERVER['DATABASE_URL']);
    }

    public function testScopeIsSelectedAndReturned(): void
    {
        [$manifest, $provider] = $this->project(
            "DATABASE_URL=postgres://db\nSENTRY_DSN=https://sentry\n",
        );
        $builder = SecretSpec::builder()
            ->withPath($manifest)
            ->withProvider($provider)
            ->withScope('database')
            ->withReason('php scoped test');

        $resolved = $builder->load();
        self::assertSame('database', $resolved->scope);
        self::assertSame(['DATABASE_URL'], \array_keys($resolved->secrets));

        $report = $builder->report();
        self::assertSame('database', $report->scope);
        self::assertSame(['DATABASE_URL'], \array_map(
            static fn (SecretReport $secret): string => $secret->name,
            $report->secrets,
        ));
    }

    public function testMissingRequiredRaises(): void
    {
        [$manifest, $provider] = $this->project('');

        try {
            SecretSpec::builder()
                ->withPath($manifest)
                ->withProvider($provider)
                ->withReason('php test')
                ->load();
            self::fail('expected MissingRequiredException');
        } catch (MissingRequiredException $e) {
            self::assertContains('DATABASE_URL', $e->missing);
        }
    }

    public function testAsPathReturnsReadableFile(): void
    {
        $manifest = <<<'TOML'
            [project]
            name = "php-test"
            revision = "1.0"

            [profiles.default]
            TLS_CERT = { description = "cert", required = true, as_path = true }
            TOML;
        [$manifestPath, $provider] = $this->project("TLS_CERT=----cert----\n", $manifest);

        $resolved = SecretSpec::builder()
            ->withPath($manifestPath)
            ->withProvider($provider)
            ->withReason('php test')
            ->load();

        try {
            $cert = $resolved->secrets['TLS_CERT'];
            self::assertTrue($cert->asPath);
            self::assertNull($cert->value);
            self::assertSame('----cert----', \file_get_contents($cert->get()));
        } finally {
            // Remove the 0400 as_path temp file so no secret-bearing file lingers.
            $resolved->close();
        }
    }

    public function testInvalidManifestRaisesError(): void
    {
        try {
            SecretSpec::builder()
                ->withPath('/definitely/does/not/exist/secretspec.toml')
                ->withReason('php test')
                ->load();
            self::fail('expected SecretSpecException');
        } catch (MissingRequiredException $e) {
            self::fail('expected a transport error, not MissingRequiredException');
        } catch (SecretSpecException $e) {
            self::assertNotEmpty($e->kind);
        }
    }

    private static function removeDir(string $dir): void
    {
        if (!\is_dir($dir)) {
            return;
        }
        foreach (\scandir($dir) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $dir . \DIRECTORY_SEPARATOR . $entry;
            \is_dir($path) ? self::removeDir($path) : @\unlink($path);
        }
        @\rmdir($dir);
    }
}
