import 'dart:ffi';

import 'package:ffi/ffi.dart';

const _nativeAssetId = 'package:monosecret/src/native_bindings.dart';

@Native<Pointer<Utf8> Function(Pointer<Utf8>)>(
  symbol: 'monosecret_resolve',
  assetId: _nativeAssetId,
)
external Pointer<Utf8> _monosecretResolve(Pointer<Utf8> request);

@Native<Void Function(Pointer<Utf8>)>(
  symbol: 'monosecret_free',
  assetId: _nativeAssetId,
  isLeaf: true,
)
external void _monosecretFree(Pointer<Utf8> pointer);

@Native<Pointer<Utf8> Function()>(
  symbol: 'monosecret_abi_version',
  assetId: _nativeAssetId,
  isLeaf: true,
)
external Pointer<Utf8> _monosecretAbiVersion();

String nativeAbiVersion() {
  final pointer = _monosecretAbiVersion();
  if (pointer == nullptr) {
    throw StateError('monosecret_abi_version returned a null pointer.');
  }

  return pointer.toDartString();
}

String nativeResolve(String requestJson) {
  final request = requestJson.toNativeUtf8(allocator: calloc);

  try {
    final response = _monosecretResolve(request);
    if (response == nullptr) {
      throw StateError('monosecret_resolve returned a null pointer.');
    }

    try {
      return response.toDartString();
    } finally {
      _monosecretFree(response);
    }
  } finally {
    calloc.free(request);
  }
}
