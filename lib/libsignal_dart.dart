/// Dart bindings for the Signal protocol — X3DH/PQXDH key agreement and the
/// Double Ratchet — built directly on libsignal's Rust core.
///
/// The native library owns the protocol state in memory. This package never
/// implements cryptography itself; it moves bytes across the FFI boundary and
/// hands back the rows the caller has to persist.
///
/// The shape of a client:
///
/// ```dart
/// final identity = SignalSession.generateIdentity();   // once, at registration
/// final session = SignalSession.open(
///   identity: identity,
///   name: myUserId,
///   deviceId: 1,
/// );
/// for (final record in await database.loadKeyMaterial()) {
///   session.load(record);                              // every launch
/// }
/// ...
/// final message = session.encrypt(peerId, peerDevice, utf8.encode(text));
/// await database.persist(session.takeDirty());         // after every operation
/// ```
///
/// Persisting what [SignalSession.takeDirty] returns is not optional. The
/// ratchet advances on every message, and a state that is not written is a
/// message that cannot be decrypted after a restart.
library;

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'src/bindings.dart';
import 'src/wire.dart';

export 'src/bindings.dart' show SignalException;
export 'src/wire.dart' show RecordKind, StoredRecord, WireFormatException;

/// Field tags in a prekey bundle. Mirrors the `TAG_*` constants in Rust.
const int _tagRegistrationId = 1;
const int _tagDeviceId = 2;
const int _tagPreKeyId = 3;
const int _tagPreKeyPublic = 4;
const int _tagSignedPreKeyId = 5;
const int _tagSignedPreKeyPublic = 6;
const int _tagSignedPreKeySignature = 7;
const int _tagKyberPreKeyId = 8;
const int _tagKyberPreKeyPublic = 9;
const int _tagKyberPreKeySignature = 10;
const int _tagIdentityKey = 11;
const int _tagName = 12;

/// Which kind of envelope a ciphertext is. The values are libsignal's own, and
/// travel alongside the ciphertext so the receiver knows how to parse it.
enum CiphertextType {
  /// A normal ratchet message, on an established session.
  whisper(2),

  /// The first message of a session: carries the sender's ephemeral key and the
  /// ids of the prekeys it consumed.
  preKey(3);

  const CiphertextType(this.code);

  final int code;

  static CiphertextType fromCode(int code) => values.firstWhere(
        (type) => type.code == code,
        orElse: () =>
            throw SignalException('unknown ciphertext message type $code'),
      );
}

/// A device's long-term identity. Losing it means a new safety number with
/// every contact, so it belongs in the encrypted database, not in preferences.
class DeviceIdentity {
  const DeviceIdentity({required this.keyPair, required this.registrationId});

  /// The serialized identity key pair — private material.
  final Uint8List keyPair;

  /// The registration id published with this device's bundles.
  final int registrationId;
}

/// A one-time prekey as published to the server.
class PublicPreKey {
  const PublicPreKey({required this.id, required this.publicKey});

  final int id;
  final Uint8List publicKey;
}

/// A signed or Kyber prekey as published to the server.
class SignedPublicPreKey {
  const SignedPublicPreKey({
    required this.id,
    required this.publicKey,
    required this.signature,
  });

  final int id;
  final Uint8List publicKey;

  /// Signed by the identity key, so a peer can tell the server did not
  /// substitute a prekey of its own.
  final Uint8List signature;
}

/// What the key directory returns for one device of one user.
///
/// [preKeyId] and [preKeyPublic] are null when the directory has run out of
/// one-time prekeys for that device. The session still forms; only the first
/// message has weaker forward secrecy. Running out should raise an alert on the
/// server rather than a failure on the client.
class PreKeyBundle {
  const PreKeyBundle({
    required this.name,
    required this.deviceId,
    required this.registrationId,
    required this.identityKey,
    required this.signedPreKey,
    required this.kyberPreKey,
    this.preKey,
  });

  final String name;
  final int deviceId;
  final int registrationId;
  final Uint8List identityKey;
  final SignedPublicPreKey signedPreKey;
  final SignedPublicPreKey kyberPreKey;
  final PublicPreKey? preKey;

  Uint8List _encode() {
    final writer = WireWriter()
      ..fieldText(_tagName, name)
      ..fieldU32(_tagDeviceId, deviceId)
      ..fieldU32(_tagRegistrationId, registrationId)
      ..field(_tagIdentityKey, identityKey)
      ..fieldU32(_tagSignedPreKeyId, signedPreKey.id)
      ..field(_tagSignedPreKeyPublic, signedPreKey.publicKey)
      ..field(_tagSignedPreKeySignature, signedPreKey.signature)
      ..fieldU32(_tagKyberPreKeyId, kyberPreKey.id)
      ..field(_tagKyberPreKeyPublic, kyberPreKey.publicKey)
      ..field(_tagKyberPreKeySignature, kyberPreKey.signature);
    final oneTime = preKey;
    if (oneTime != null) {
      writer
        ..fieldU32(_tagPreKeyId, oneTime.id)
        ..field(_tagPreKeyPublic, oneTime.publicKey);
    }
    return writer.finish();
  }
}

/// One encrypted message, addressed to one device.
class EncryptedMessage {
  const EncryptedMessage({required this.type, required this.ciphertext});

  final CiphertextType type;
  final Uint8List ciphertext;
}

/// The protocol state for one local device.
///
/// A session is not thread-safe and holds native memory: call [close] when the
/// user signs out. Every method that changes state adds rows to [takeDirty].
class SignalSession {
  SignalSession._(this._bindings, this._handle, this.name, this.deviceId);

  static Bindings? _shared;

  static Bindings get _library => _shared ??= Bindings.open();

  /// Point the package at an explicit native library. Useful in tests and on
  /// desktop; on mobile the bundled library is found automatically.
  static void loadLibraryFrom(String path) =>
      _shared = Bindings(DynamicLibrary.open(path));

  final Bindings _bindings;
  Pointer<Void> _handle;

  /// The local user's stable id — whatever the server uses to address them.
  final String name;

  /// Which of this user's devices this is. libsignal allows 1..=127.
  final int deviceId;

  bool get isClosed => _handle == nullptr;

  /// Generate a fresh identity. Call once per device, at registration.
  static DeviceIdentity generateIdentity() {
    final bindings = _library;
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    final outRegistration = calloc<Uint32>();
    try {
      bindings.check(
        bindings.identityGenerate(outPtr, outLen, outRegistration),
        'cannot generate an identity',
      );
      return DeviceIdentity(
        keyPair: bindings.takeBuffer(outPtr.value, outLen.value),
        registrationId: outRegistration.value,
      );
    } finally {
      calloc
        ..free(outPtr)
        ..free(outLen)
        ..free(outRegistration);
    }
  }

  /// Open a session around an identity, empty until [load] has replayed the
  /// stored key material.
  static SignalSession open({
    required DeviceIdentity identity,
    required String name,
    required int deviceId,
  }) {
    final bindings = _library;
    final outHandle = calloc<Pointer<Void>>();
    try {
      final status = withBytes(
        identity.keyPair,
        (keyPtr, keyLen) => withBytes(
          _utf8(name),
          (namePtr, nameLen) => bindings.storeNew(
            keyPtr,
            keyLen,
            identity.registrationId,
            namePtr,
            nameLen,
            deviceId,
            outHandle,
          ),
        ),
      );
      bindings.check(status, 'cannot open a session store');
      return SignalSession._(bindings, outHandle.value, name, deviceId);
    } finally {
      calloc.free(outHandle);
    }
  }

  /// Replay one persisted row into the store. Loading is not a change, so it
  /// does not come back out of [takeDirty].
  void load(StoredRecord record) {
    final value = record.value;
    if (value == null) {
      throw SignalException('cannot load a deleted record: ${record.key}');
    }
    final status = withBytes(
      _utf8(record.key),
      (keyPtr, keyLen) => withBytes(
        value,
        (valuePtr, valueLen) => _bindings.storeLoad(
          _alive,
          record.kind.code,
          keyPtr,
          keyLen,
          valuePtr,
          valueLen,
        ),
      ),
    );
    _bindings.check(status, 'cannot load ${record.kind.name} ${record.key}');
  }

  /// Replay a whole database's worth of rows.
  void loadAll(Iterable<StoredRecord> records) => records.forEach(load);

  /// Everything that changed since the last call. Write these rows before
  /// calling again: the list is drained, not re-reported.
  List<StoredRecord> takeDirty() {
    final frame = _buffer(
      (outPtr, outLen) => _bindings.takeDirty(_alive, outPtr, outLen),
      'cannot read pending changes',
    );
    return WireReader(frame).records();
  }

  /// How many rows are waiting to be written. A number that keeps climbing
  /// means the caller is not draining [takeDirty].
  int get pendingWrites {
    final out = calloc<Size>();
    try {
      _bindings.check(
        _bindings.pending(_alive, out),
        'cannot count pending changes',
      );
      return out.value;
    } finally {
      calloc.free(out);
    }
  }

  /// The public identity key, for upload to the key directory.
  Uint8List get identityKey => _buffer(
        (outPtr, outLen) => _bindings.identityPublic(_alive, outPtr, outLen),
        'cannot read the identity key',
      );

  /// Generate `count` one-time prekeys starting at `startId`, and return their
  /// public halves for upload.
  ///
  /// Ids must never be reused for a device: a peer holding a stale bundle would
  /// otherwise be handed a key this device has already spent. Keep a high-water
  /// mark and always start above it.
  List<PublicPreKey> generatePreKeys({
    required int startId,
    required int count,
  }) {
    final frame = _buffer(
      (outPtr, outLen) =>
          _bindings.generatePreKeys(_alive, startId, count, outPtr, outLen),
      'cannot generate one-time prekeys',
    );
    return WireReader(frame).records().map((record) {
      final value = record.value;
      if (value == null) {
        throw const WireFormatException('a generated prekey has no public key');
      }
      return PublicPreKey(id: int.parse(record.key), publicKey: value);
    }).toList(growable: false);
  }

  /// Generate the signed prekey, rotated on a schedule (Signal uses ~2 days).
  SignedPublicPreKey generateSignedPreKey(int id) => _signedPreKey(
        _bindings.generateSignedPreKey,
        id,
        _tagSignedPreKeyId,
        _tagSignedPreKeyPublic,
        _tagSignedPreKeySignature,
        'cannot generate a signed prekey',
      );

  /// Generate the Kyber1024 prekey. This is what makes key agreement
  /// post-quantum; the bundle requires it.
  SignedPublicPreKey generateKyberPreKey(int id) => _signedPreKey(
        _bindings.generateKyberPreKey,
        id,
        _tagKyberPreKeyId,
        _tagKyberPreKeyPublic,
        _tagKyberPreKeySignature,
        'cannot generate a kyber prekey',
      );

  /// Start a session with one device, from a bundle fetched out of the
  /// directory. Safe to call again for a device we already know: it replaces
  /// the session rather than corrupting it.
  void processPreKeyBundle(PreKeyBundle bundle) {
    final status = withBytes(
      bundle._encode(),
      (ptr, len) => _bindings.processPreKeyBundle(_alive, ptr, len),
    );
    _bindings.check(
      status,
      'cannot start a session with ${bundle.name}.${bundle.deviceId}',
    );
  }

  /// Encrypt one message for one device.
  ///
  /// A message to a user with several devices is several calls — one per
  /// device, each producing different bytes. There is no group ciphertext here.
  EncryptedMessage encrypt({
    required String toName,
    required int toDeviceId,
    required List<int> plaintext,
  }) {
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    final outType = calloc<Uint32>();
    try {
      final status = withBytes(
        _utf8(toName),
        (namePtr, nameLen) => withBytes(
          plaintext,
          (textPtr, textLen) => _bindings.encrypt(
            _alive,
            namePtr,
            nameLen,
            toDeviceId,
            textPtr,
            textLen,
            outPtr,
            outLen,
            outType,
          ),
        ),
      );
      _bindings.check(status, 'cannot encrypt for $toName.$toDeviceId');
      return EncryptedMessage(
        type: CiphertextType.fromCode(outType.value),
        ciphertext: _bindings.takeBuffer(outPtr.value, outLen.value),
      );
    } finally {
      calloc
        ..free(outPtr)
        ..free(outLen)
        ..free(outType);
    }
  }

  /// Decrypt one message from one device.
  ///
  /// Throws when the message is a replay, when it was encrypted for a different
  /// device, or when the sender's identity key has changed. Those are all
  /// normal conditions on a real network and belong in the UI, not in a crash.
  Uint8List decrypt({
    required String fromName,
    required int fromDeviceId,
    required CiphertextType type,
    required List<int> ciphertext,
  }) {
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      final status = withBytes(
        _utf8(fromName),
        (namePtr, nameLen) => withBytes(
          ciphertext,
          (textPtr, textLen) => _bindings.decrypt(
            _alive,
            namePtr,
            nameLen,
            fromDeviceId,
            type.code,
            textPtr,
            textLen,
            outPtr,
            outLen,
          ),
        ),
      );
      _bindings.check(status, 'cannot decrypt from $fromName.$fromDeviceId');
      return _bindings.takeBuffer(outPtr.value, outLen.value);
    } finally {
      calloc
        ..free(outPtr)
        ..free(outLen);
    }
  }

  /// Whether a usable session with this device already exists. When false, the
  /// caller should fetch a bundle before encrypting.
  bool hasSession(String peerName, int peerDeviceId) =>
      _flag(
        (out) => withBytes(
          _utf8(peerName),
          (namePtr, nameLen) =>
              _bindings.hasSession(_alive, namePtr, nameLen, peerDeviceId, out),
        ),
        'cannot check the session with $peerName.$peerDeviceId',
      );

  /// Whether this identity key is the one already trusted for this device.
  /// False for a *changed* key is what should raise the safety-number banner.
  bool isTrustedIdentity({
    required String peerName,
    required int peerDeviceId,
    required List<int> identityKey,
  }) =>
      _flag(
        (out) => withBytes(
          _utf8(peerName),
          (namePtr, nameLen) => withBytes(
            identityKey,
            (idPtr, idLen) => _bindings.isTrustedIdentity(
              _alive,
              namePtr,
              nameLen,
              peerDeviceId,
              idPtr,
              idLen,
              out,
            ),
          ),
        ),
        'cannot check the identity of $peerName.$peerDeviceId',
      );

  /// Release the native state. Idempotent.
  void close() {
    if (_handle == nullptr) return;
    _bindings.storeFree(_handle);
    _handle = nullptr;
  }

  Pointer<Void> get _alive {
    if (_handle == nullptr) {
      throw const SignalException('this session has been closed');
    }
    return _handle;
  }

  SignedPublicPreKey _signedPreKey(
    int Function(Pointer<Void>, int, Pointer<Pointer<Uint8>>, Pointer<Size>)
        generate,
    int id,
    int idTag,
    int publicTag,
    int signatureTag,
    String what,
  ) {
    final frame = _buffer(
      (outPtr, outLen) => generate(_alive, id, outPtr, outLen),
      what,
    );
    final fields = WireReader(frame).fields();
    Uint8List required(int tag, String name) {
      final value = fields[tag];
      if (value == null) {
        throw WireFormatException('the generated prekey has no $name');
      }
      return value;
    }

    return SignedPublicPreKey(
      id: readU32(required(idTag, 'id')),
      publicKey: required(publicTag, 'public key'),
      signature: required(signatureTag, 'signature'),
    );
  }

  Uint8List _buffer(
    int Function(Pointer<Pointer<Uint8>>, Pointer<Size>) call,
    String what,
  ) {
    final outPtr = calloc<Pointer<Uint8>>();
    final outLen = calloc<Size>();
    try {
      _bindings.check(call(outPtr, outLen), what);
      return _bindings.takeBuffer(outPtr.value, outLen.value);
    } finally {
      calloc
        ..free(outPtr)
        ..free(outLen);
    }
  }

  bool _flag(int Function(Pointer<Uint8>) call, String what) {
    final out = calloc<Uint8>();
    try {
      _bindings.check(call(out), what);
      return out.value != 0;
    } finally {
      calloc.free(out);
    }
  }
}

List<int> _utf8(String value) =>
    Uint8List.fromList(const Utf8Encoder().convert(value));
