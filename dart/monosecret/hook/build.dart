import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:code_assets/code_assets.dart';
import 'package:crypto/crypto.dart';
import 'package:hooks/hooks.dart';

import '../lib/src/version.dart';

const _assetName = 'src/native_bindings.dart';
const _maxLibraryBytes = 256 * 1024 * 1024;
const _networkTimeout = Duration(seconds: 30);

void main(List<String> arguments) async {
  await build(arguments, (input, output) async {
    if (!input.config.buildCodeAssets) {
      return;
    }

    final artifact = _artifactFor(
      input.config.code.targetOS,
      input.config.code.targetArchitecture,
    );
    final outputFile = input.outputDirectory.resolve(artifact.libraryName);
    final localDirectory = input.userDefines.path('native_library_directory');

    if (localDirectory == null) {
      await _downloadVerifiedArtifact(
        artifact: artifact,
        outputFile: outputFile,
        sharedOutputDirectory: input.outputDirectoryShared,
      );
    } else {
      final directory = Directory.fromUri(localDirectory);
      final localFile = directory.uri.resolve(artifact.libraryName);
      final file = File.fromUri(localFile);
      if (!await file.exists()) {
        throw StateError(
          'The Monosecret native library override does not exist: '
          '${file.path}',
        );
      }

      output.dependencies.add(localFile);
      await file.copy(outputFile.toFilePath());
    }

    output.assets.code.add(
      CodeAsset(
        package: input.packageName,
        name: _assetName,
        file: outputFile,
        linkMode: DynamicLoadingBundled(),
      ),
    );
  });
}

_Artifact _artifactFor(OS os, Architecture architecture) {
  final target = switch ((os, architecture)) {
    (OS.linux, Architecture.x64) => 'x86_64-unknown-linux-gnu',
    (OS.linux, Architecture.arm64) => 'aarch64-unknown-linux-gnu',
    (OS.macOS, Architecture.x64) => 'x86_64-apple-darwin',
    (OS.macOS, Architecture.arm64) => 'aarch64-apple-darwin',
    (OS.windows, Architecture.x64) => 'x86_64-pc-windows-msvc',
    (OS.windows, Architecture.arm64) => 'aarch64-pc-windows-msvc',
    _ => throw UnsupportedError(
      'Monosecret does not provide a native library for $os/$architecture. '
      'Server releases support Linux glibc, macOS, and Windows on x64 and '
      'ARM64.',
    ),
  };
  final extension = switch (os) {
    OS.linux => 'so',
    OS.macOS => 'dylib',
    OS.windows => 'dll',
    _ => throw UnsupportedError('Unsupported Monosecret server OS: $os.'),
  };
  final libraryName = switch (os) {
    OS.windows => 'monosecret_ffi.dll',
    OS.linux => 'libmonosecret_ffi.so',
    OS.macOS => 'libmonosecret_ffi.dylib',
    _ => throw UnsupportedError('Unsupported Monosecret server OS: $os.'),
  };

  return _Artifact(
    target: target,
    extension: extension,
    libraryName: libraryName,
  );
}

Future<void> _downloadVerifiedArtifact({
  required _Artifact artifact,
  required Uri outputFile,
  required Uri sharedOutputDirectory,
}) async {
  final releaseTag = 'v$monosecretVersion';
  final stem = 'monosecret-ffi-${artifact.target}-$releaseTag';
  final payloadName = '$stem.${artifact.extension}';
  final releaseBase = Uri.parse(
    'https://github.com/ifiokjr/monosecret/releases/download/'
    '$releaseTag/',
  );
  final checksumUri = releaseBase.resolve('$stem.sha256');
  final payloadUri = releaseBase.resolve(payloadName);
  final checksumText = utf8.decode(
    await _downloadBytes(checksumUri, maximumBytes: 4096),
  );
  final expectedHash = parseChecksumSidecar(checksumText, payloadName);
  final cacheDirectory = sharedOutputDirectory.resolve(
    'monosecret/$expectedHash/',
  );
  final cachedFile = File.fromUri(cacheDirectory.resolve(payloadName));

  await cachedFile.parent.create(recursive: true);
  if (!await _hasHash(cachedFile, expectedHash)) {
    await cachedFile.deleteIfExists();
    await _downloadFile(payloadUri, cachedFile);

    if (!await _hasHash(cachedFile, expectedHash)) {
      await cachedFile.deleteIfExists();
      throw StateError(
        'SHA-256 verification failed for $payloadName from $payloadUri.',
      );
    }
  }

  await cachedFile.copy(outputFile.toFilePath());
}

/// Parses the single-entry `sha256sum` sidecar used by release assets.
String parseChecksumSidecar(String content, String payloadName) {
  final lines = const LineSplitter()
      .convert(content)
      .where((line) => line.trim().isNotEmpty)
      .toList(growable: false);
  if (lines.length != 1) {
    throw const FormatException('Invalid Monosecret SHA-256 sidecar.');
  }

  final match = RegExp(
    r'^([a-fA-F0-9]{64})[ \t]+\*?(.+)$',
  ).firstMatch(lines.single);
  final hash = match?.group(1)?.toLowerCase();
  final recordedName = match?.group(2);
  if (hash == null || recordedName == null) {
    throw const FormatException('Invalid Monosecret SHA-256 sidecar.');
  }

  if (recordedName != payloadName) {
    throw FormatException(
      'Checksum sidecar names $recordedName instead of $payloadName.',
    );
  }

  return hash;
}

Future<bool> _hasHash(File file, String expectedHash) async {
  if (!await file.exists()) {
    return false;
  }

  final actual = await sha256.bind(file.openRead()).first;
  return actual.toString() == expectedHash;
}

Future<List<int>> _downloadBytes(Uri uri, {required int maximumBytes}) async {
  final bytes = <int>[];
  await _withResponse(uri, (response) async {
    await for (final chunk in response.timeout(_networkTimeout)) {
      bytes.addAll(chunk);
      if (bytes.length > maximumBytes) {
        throw StateError('Download from $uri exceeded $maximumBytes bytes.');
      }
    }
  });

  return bytes;
}

Future<void> _downloadFile(Uri uri, File destination) async {
  final suffix = Random.secure().nextInt(1 << 32).toRadixString(16);
  final temporary = File('${destination.path}.$suffix.tmp');
  final sink = temporary.openWrite();
  var received = 0;

  try {
    await _withResponse(uri, (response) async {
      await for (final chunk in response.timeout(_networkTimeout)) {
        received += chunk.length;
        if (received > _maxLibraryBytes) {
          throw StateError(
            'Download from $uri exceeded $_maxLibraryBytes bytes.',
          );
        }
        sink.add(chunk);
      }
    });
    await sink.close();
    await temporary.rename(destination.path);
  } catch (_) {
    await sink.close();
    await temporary.deleteIfExists();
    rethrow;
  }
}

Future<void> _withResponse(
  Uri uri,
  Future<void> Function(HttpClientResponse response) consume,
) async {
  final client = HttpClient()..connectionTimeout = _networkTimeout;

  try {
    final request = await client.getUrl(uri).timeout(_networkTimeout);
    final response = await request.close().timeout(_networkTimeout);
    if (response.statusCode < 200 || response.statusCode >= 300) {
      await response.drain<void>();
      throw HttpException(
        'Download failed with HTTP ${response.statusCode}.',
        uri: uri,
      );
    }

    await consume(response);
  } finally {
    client.close(force: true);
  }
}

final class _Artifact {
  const _Artifact({
    required this.target,
    required this.extension,
    required this.libraryName,
  });

  final String target;
  final String extension;
  final String libraryName;
}

extension on File {
  Future<void> deleteIfExists() async {
    if (await exists()) {
      await delete();
    }
  }
}
