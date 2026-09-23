import 'dart:ffi';
import 'dart:io';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

/// The raw C ABI. Everything above this file works in Dart types; everything
/// below it is `native/src/lib.rs`. The two must be changed together, and
/// [Bindings.abiVersion] is checked at load time so a stale bundled library
/// fails loudly instead of reading the wrong bytes.

const int _statusOk = 0;
const int _statusBadArgument = 2;

/// The ABI this Dart code was written against. Mirrors `ABI_VERSION` in Rust.
const int expectedAbiVersion = 1;

/// A failure reported by the native library.
class SignalException implements Exception {
  const SignalException(this.message, {this.status = 1});

  final String message;
  final int status;

  @override
  String toString() => 'SignalException: $message';
}

typedef _AbiVersionC = Uint32 Function();
typedef _AbiVersionDart = int Function();

typedef _FreeC = Void Function(Pointer<Uint8>, Size);
typedef _FreeDart = void Function(Pointer<Uint8>, int);

typedef _LastErrorC = Int32 Function(Pointer<Pointer<Uint8>>, Pointer<Size>);
typedef _LastErrorDart = int Function(Pointer<Pointer<Uint8>>, Pointer<Size>);

typedef _IdentityGenerateC = Int32 Function(
    Pointer<Pointer<Uint8>>, Pointer<Size>, Pointer<Uint32>);
typedef _IdentityGenerateDart = int Function(
    Pointer<Pointer<Uint8>>, Pointer<Size>, Pointer<Uint32>);

typedef _StoreNewC = Int32 Function(Pointer<Uint8>, Size, Uint32,
    Pointer<Uint8>, Size, Uint32, Pointer<Pointer<Void>>);
typedef _StoreNewDart = int Function(Pointer<Uint8>, int, int, Pointer<Uint8>,
    int, int, Pointer<Pointer<Void>>);

typedef _StoreFreeC = Void Function(Pointer<Void>);
typedef _StoreFreeDart = void Function(Pointer<Void>);

typedef _StoreLoadC = Int32 Function(
    Pointer<Void>, Uint32, Pointer<Uint8>, Size, Pointer<Uint8>, Size);
typedef _StoreLoadDart = int Function(
    Pointer<Void>, int, Pointer<Uint8>, int, Pointer<Uint8>, int);

typedef _BufferOutC = Int32 Function(
    Pointer<Void>, Pointer<Pointer<Uint8>>, Pointer<Size>);
typedef _BufferOutDart = int Function(
    Pointer<Void>, Pointer<Pointer<Uint8>>, Pointer<Size>);

typedef _GenerateOneC = Int32 Function(
    Pointer<Void>, Uint32, Pointer<Pointer<Uint8>>, Pointer<Size>);
typedef _GenerateOneDart = int Function(
    Pointer<Void>, int, Pointer<Pointer<Uint8>>, Pointer<Size>);

typedef _GenerateManyC = Int32 Function(
    Pointer<Void>, Uint32, Uint32, Pointer<Pointer<Uint8>>, Pointer<Size>);
typedef _GenerateManyDart = int Function(
    Pointer<Void>, int, int, Pointer<Pointer<Uint8>>, Pointer<Size>);

typedef _ProcessBundleC = Int32 Function(Pointer<Void>, Pointer<Uint8>, Size);
typedef _ProcessBundleDart = int Function(Pointer<Void>, Pointer<Uint8>, int);

typedef _EncryptC = Int32 Function(
    Pointer<Void>,
    Pointer<Uint8>,
    Size,
    Uint32,
    Pointer<Uint8>,
    Size,
    Pointer<Pointer<Uint8>>,
    Pointer<Size>,
    Pointer<Uint32>);
typedef _EncryptDart = int Function(
    Pointer<Void>,
    Pointer<Uint8>,
    int,
    int,
    Pointer<Uint8>,
    int,
    Pointer<Pointer<Uint8>>,
    Pointer<Size>,
    Pointer<Uint32>);

typedef _DecryptC = Int32 Function(Pointer<Void>, Pointer<Uint8>, Size, Uint32,
    Uint32, Pointer<Uint8>, Size, Pointer<Pointer<Uint8>>, Pointer<Size>);
typedef _DecryptDart = int Function(Pointer<Void>, Pointer<Uint8>, int, int, int,
    Pointer<Uint8>, int, Pointer<Pointer<Uint8>>, Pointer<Size>);

typedef _PendingC = Int32 Function(Pointer<Void>, Pointer<Size>);
typedef _PendingDart = int Function(Pointer<Void>, Pointer<Size>);

typedef _HasSessionC = Int32 Function(
    Pointer<Void>, Pointer<Uint8>, Size, Uint32, Pointer<Uint8>);
typedef _HasSessionDart = int Function(
    Pointer<Void>, Pointer<Uint8>, int, int, Pointer<Uint8>);

typedef _IsTrustedC = Int32 Function(Pointer<Void>, Pointer<Uint8>, Size, Uint32,
    Pointer<Uint8>, Size, Pointer<Uint8>);
typedef _IsTrustedDart = int Function(Pointer<Void>, Pointer<Uint8>, int, int,
    Pointer<Uint8>, int, Pointer<Uint8>);

class Bindings {
  Bindings(this._library)
      : abiVersion = _library
            .lookupFunction<_AbiVersionC, _AbiVersionDart>(
                'signal_dart_abi_version')(),
        free = _library.lookupFunction<_FreeC, _FreeDart>('signal_dart_free'),
        lastError = _library.lookupFunction<_LastErrorC, _LastErrorDart>(
            'signal_dart_last_error'),
        identityGenerate =
            _library.lookupFunction<_IdentityGenerateC, _IdentityGenerateDart>(
                'signal_dart_identity_generate'),
        storeNew = _library
            .lookupFunction<_StoreNewC, _StoreNewDart>('signal_dart_store_new'),
        storeFree = _library.lookupFunction<_StoreFreeC, _StoreFreeDart>(
            'signal_dart_store_free'),
        storeLoad = _library.lookupFunction<_StoreLoadC, _StoreLoadDart>(
            'signal_dart_store_load'),
        takeDirty = _library.lookupFunction<_BufferOutC, _BufferOutDart>(
            'signal_dart_store_take_dirty'),
        pending = _library.lookupFunction<_PendingC, _PendingDart>(
            'signal_dart_store_pending'),
        identityPublic = _library.lookupFunction<_BufferOutC, _BufferOutDart>(
            'signal_dart_identity_public'),
        generatePreKeys =
            _library.lookupFunction<_GenerateManyC, _GenerateManyDart>(
                'signal_dart_generate_pre_keys'),
        generateSignedPreKey =
            _library.lookupFunction<_GenerateOneC, _GenerateOneDart>(
                'signal_dart_generate_signed_pre_key'),
        generateKyberPreKey =
            _library.lookupFunction<_GenerateOneC, _GenerateOneDart>(
                'signal_dart_generate_kyber_pre_key'),
        processPreKeyBundle =
            _library.lookupFunction<_ProcessBundleC, _ProcessBundleDart>(
                'signal_dart_process_pre_key_bundle'),
        encrypt = _library
            .lookupFunction<_EncryptC, _EncryptDart>('signal_dart_encrypt'),
        decrypt = _library
            .lookupFunction<_DecryptC, _DecryptDart>('signal_dart_decrypt'),
        hasSession = _library.lookupFunction<_HasSessionC, _HasSessionDart>(
            'signal_dart_has_session'),
        isTrustedIdentity =
            _library.lookupFunction<_IsTrustedC, _IsTrustedDart>(
                'signal_dart_is_trusted_identity') {
    if (abiVersion != expectedAbiVersion) {
      throw SignalException(
        'the bundled native library speaks ABI $abiVersion, '
        'this Dart code speaks ABI $expectedAbiVersion',
      );
    }
  }

  /// Load the library, or throw explaining where it was looked for.
  ///
  /// `LIBSIGNAL_DART_LIBRARY` overrides the search, which is how the tests point
  /// at the freshly built `target/release` copy.
  factory Bindings.open() {
    final override = Platform.environment['LIBSIGNAL_DART_LIBRARY'];
    if (override != null && override.isNotEmpty) {
      return Bindings(DynamicLibrary.open(override));
    }
    // On iOS the library is linked into the app binary, so there is no file to
    // open and symbols come from the process itself.
    if (Platform.isIOS || Platform.isMacOS) {
      try {
        return Bindings(DynamicLibrary.process());
      } on ArgumentError {
        // Fall through to the file-based lookup below for a dylib build.
      }
    }
    final attempts = <String>[
      if (Platform.isWindows) 'libsignal_dart.dll',
      if (Platform.isMacOS) 'liblibsignal_dart.dylib',
      if (Platform.isAndroid || Platform.isLinux) 'liblibsignal_dart.so',
    ];
    final failures = <String>[];
    for (final name in attempts) {
      try {
        return Bindings(DynamicLibrary.open(name));
      } on ArgumentError catch (error) {
        failures.add('$name: ${error.message}');
      }
    }
    throw SignalException(
      'cannot load the libsignal_dart native library. Tried: '
      '${failures.isEmpty ? 'nothing — unsupported platform' : failures.join('; ')}. '
      'Set LIBSIGNAL_DART_LIBRARY to an explicit path to override.',
    );
  }

  // ignore: unused_field
  final DynamicLibrary _library;

  final int abiVersion;
  final _FreeDart free;
  final _LastErrorDart lastError;
  final _IdentityGenerateDart identityGenerate;
  final _StoreNewDart storeNew;
  final _StoreFreeDart storeFree;
  final _StoreLoadDart storeLoad;
  final _BufferOutDart takeDirty;
  final _PendingDart pending;
  final _BufferOutDart identityPublic;
  final _GenerateManyDart generatePreKeys;
  final _GenerateOneDart generateSignedPreKey;
  final _GenerateOneDart generateKyberPreKey;
  final _ProcessBundleDart processPreKeyBundle;
  final _EncryptDart encrypt;
  final _DecryptDart decrypt;
  final _HasSessionDart hasSession;
  final _IsTrustedDart isTrustedIdentity;

  /// Turn a non-zero status into an exception carrying the native message.
  void check(int status, String what) {
    if (status == _statusOk) return;
    if (status == _statusBadArgument) {
      throw SignalException('$what: a required pointer was null', status: status);
    }
    throw SignalException('$what: ${_drainError()}', status: status);
  }

  String _drainError() {
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      if (lastError(outPtr, outLen) != _statusOk) {
        return 'the native library did not report a reason';
      }
      final bytes = takeBuffer(outPtr.value, outLen.value);
      return bytes.isEmpty
          ? 'the native library did not report a reason'
          : String.fromCharCodes(bytes);
    } finally {
      calloc
        ..free(outPtr)
        ..free(outLen);
    }
  }

  /// Copy a buffer the native side allocated, then hand the memory back.
  /// Dart never frees Rust memory itself, and never holds a native pointer
  /// past the call that produced it.
  Uint8List takeBuffer(Pointer<Uint8> ptr, int length) {
    if (ptr == nullptr || length == 0) {
      if (ptr != nullptr) free(ptr, length);
      return Uint8List(0);
    }
    final copy = Uint8List.fromList(ptr.asTypedList(length));
    free(ptr, length);
    return copy;
  }
}

/// Copy `bytes` into native memory for the duration of `body`.
T withBytes<T>(List<int> bytes, T Function(Pointer<Uint8> ptr, int len) body) {
  if (bytes.isEmpty) return body(nullptr, 0);
  final buffer = calloc<Uint8>(bytes.length);
  try {
    buffer.asTypedList(bytes.length).setAll(0, bytes);
    return body(buffer, bytes.length);
  } finally {
    calloc.free(buffer);
  }
}
