<?php

declare(strict_types=1);

namespace Secretspec\Tests;

use PHPUnit\Framework\TestCase;
use Secretspec\CallerContext;
use Secretspec\MissingRequiredException;
use Secretspec\Native;
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
        DEV_SESSION_SECRET = { description = "Development-only session secret", required = false, default = "development-only-secret" }
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

    public function testLegacyFfiBindingDoesNotRequireInlineCallSymbol(): void
    {
        $reflection = new \ReflectionClass(Native::class);

        self::assertStringNotContainsString(
            'secretspec_call',
            $reflection->getConstant('CDEF'),
        );
        self::assertStringContainsString(
            'secretspec_call',
            $reflection->getConstant('CALL_CDEF'),
        );
    }

    public function testCallerContextCanAccompanyASeparateReason(): void
    {
        [$manifest, $provider] = $this->project("DATABASE_URL=postgres://db\n");
        $resolved = SecretSpec::builder()
            ->withPath($manifest)
            ->withProvider($provider)
            ->withCaller(new CallerContext(
                name: 'git',
                version: '2.51.0',
                operation: 'credential_get',
                resource: 'github.com',
            ))
            ->withReason('push the release tag')
            ->load();

        self::assertSame('postgres://db', $resolved->secrets['DATABASE_URL']->get());
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

        $session = $resolved->secrets['DEV_SESSION_SECRET'];
        self::assertSame('development-only-secret', $session->get());
        self::assertSame('default', $session->source);

        self::assertSame(['SENTRY_DSN'], $resolved->missingOptional);
        self::assertArrayNotHasKey('SENTRY_DSN', $resolved->secrets);
    }

    public function testInlineSpecResolvesAtItsLogicalBaseDir(): void
    {
        [$manifest] = $this->project('');
        $dir = \dirname($manifest);
        \file_put_contents($dir . \DIRECTORY_SEPARATOR . 'inline.env', "TOKEN=inline-php\n");
        $spec = [
            'project' => ['name' => 'php-inline'],
            'providers' => ['env' => 'dotenv://inline.env'],
            'profiles' => ['default' => ['secrets' => [
                'TOKEN' => ['description' => 'token', 'providers' => ['env']],
            ]]],
        ];
        $resolved = SecretSpec::builder()
            ->withInlineSpec($spec, $dir)
            ->withReason('php inline test')
            ->load();

        self::assertSame('inline-php', $resolved->secrets['TOKEN']->get());
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
            $stream = $cert->open();
            try {
                self::assertSame('----cert----', \stream_get_contents($stream));
                self::assertSame(0, \fseek($stream, 4));
                self::assertSame('cert', \fread($stream, 4));
                $resolved->close();
                \rewind($stream);
                self::assertSame('----cert----', \stream_get_contents($stream));
            } finally {
                \fclose($stream);
            }
            try {
                $cert->open();
                self::fail('a closed result must not permit new reads');
            } catch (SecretSpecException $e) {
                self::assertSame('io', $e->kind);
            }
        } finally {
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

    public function testFileStreamPreservesBinaryAndEmptyContents(): void
    {
        $manifest = <<<'TOML'
            [project]
            name = "php-stream"
            revision = "1.0"
            require_reason = false
            [profiles.default]
            FILE = { description = "Binary stream fixture", as_path = true, encoding = "base64" }
            TOML;
        foreach (['', \str_repeat("\x00\xff\x80\r\n", 4096)] as $bytes) {
            [$path, $provider] = $this->project('FILE=' . \base64_encode($bytes) . "\n", $manifest);
            $result = SecretSpec::builder()->withPath($path)->withProvider($provider)->load();
            try {
                $stream = $result->secrets['FILE']->open();
                try {
                    self::assertSame('php://memory', \stream_get_meta_data($stream)['uri']);
                    self::assertSame($bytes, \stream_get_contents($stream));
                } finally {
                    \fclose($stream);
                }
            } finally {
                $result->close();
            }
        }
    }

    public function testInlineSecretCannotBeOpenedAsFile(): void
    {
        [$path, $provider] = $this->project("DATABASE_URL=postgres://db\n");
        $result = SecretSpec::builder()->withPath($path)->withProvider($provider)->withReason('test')->load();
        try {
            $this->expectException(SecretSpecException::class);
            $result->secrets['DATABASE_URL']->open();
        } finally {
            $result->close();
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
