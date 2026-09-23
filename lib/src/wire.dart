import 'dart:convert';
import 'dart:typed_data';

/// The byte format shared with the Rust side. See `native/src/wire.rs`; the two
/// files describe the same thing and must change together.
///
/// Everything is little-endian and length-prefixed. There is no JSON: keys and
/// ciphertext are already bytes, and re-encoding them would cost more than the
/// format saves.

/// `valueLength` sentinel meaning the row should be deleted rather than written.
const int _tombstone = 0xFFFFFFFF;

/// Which store a record belongs to. Mirrors the `KIND_*` constants in Rust.
enum RecordKind {
  session(1),
  preKey(2),
  signedPreKey(3),
  kyberPreKey(4),
  identity(5);

  const RecordKind(this.code);

  final int code;

  static RecordKind fromCode(int code) => values.firstWhere(
        (kind) => kind.code == code,
        orElse: () => throw WireFormatException('unknown record kind $code'),
      );
}

/// The separator between a name and a device id inside a record key. A control
/// character, so it cannot collide with a UUID or a username. Mirrors
/// `ADDRESS_SEPARATOR` in `native/src/store.rs`.
const String _addressSeparator = '\u0001';

/// Who a session or identity record belongs to.
class SignalAddress {
  const SignalAddress(this.name, this.deviceId);

  final String name;
  final int deviceId;

  @override
  bool operator ==(Object other) =>
      other is SignalAddress && other.name == name && other.deviceId == deviceId;

  @override
  int get hashCode => Object.hash(name, deviceId);

  @override
  String toString() => '$name.$deviceId';
}

/// One row of key material. [value] is null when the row should be deleted —
/// which is how a spent one-time prekey is retired.
class StoredRecord {
  const StoredRecord(this.kind, this.key, this.value);

  final RecordKind kind;
  final String key;
  final Uint8List? value;

  bool get isDeletion => value == null;

  /// The peer this row is about, for session and identity rows. Null for
  /// prekeys, whose key is an id rather than an address.
  SignalAddress? get address {
    if (kind != RecordKind.session && kind != RecordKind.identity) return null;
    final at = key.indexOf(_addressSeparator);
    if (at <= 0) return null;
    final deviceId = int.tryParse(key.substring(at + 1));
    if (deviceId == null) return null;
    return SignalAddress(key.substring(0, at), deviceId);
  }

  @override
  String toString() =>
      'StoredRecord(${kind.name}, $key, ${value == null ? 'deleted' : '${value!.length} bytes'})';
}

class WireFormatException implements Exception {
  const WireFormatException(this.message);

  final String message;

  @override
  String toString() => 'WireFormatException: $message';
}

/// Builds a frame: a count followed by that many fields or records.
class WireWriter {
  final BytesBuilder _body = BytesBuilder(copy: false);
  int _count = 0;

  void field(int tag, List<int> value) {
    _body
      ..add(_u32(tag))
      ..add(_u32(value.length))
      ..add(value);
    _count++;
  }

  void fieldU32(int tag, int value) => field(tag, _u32(value));

  void fieldText(int tag, String value) => field(tag, utf8.encode(value));

  void record(RecordKind kind, String key, List<int>? value) {
    final keyBytes = utf8.encode(key);
    _body
      ..add(_u32(kind.code))
      ..add(_u32(keyBytes.length))
      ..add(keyBytes);
    if (value == null) {
      _body.add(_u32(_tombstone));
    } else {
      _body
        ..add(_u32(value.length))
        ..add(value);
    }
    _count++;
  }

  Uint8List finish() {
    final out = BytesBuilder(copy: false)
      ..add(_u32(_count))
      ..add(_body.takeBytes());
    return out.takeBytes();
  }
}

/// Reads a frame written by Rust.
class WireReader {
  WireReader(this._data) : _view = ByteData.sublistView(_data) {
    if (_data.length < 4) {
      throw const WireFormatException('truncated frame: missing count');
    }
    count = _view.getUint32(0, Endian.little);
  }

  final Uint8List _data;
  final ByteData _view;
  late final int count;
  int _at = 4;

  int _u32() {
    if (_at + 4 > _data.length) {
      throw const WireFormatException('truncated frame: expected a length');
    }
    final value = _view.getUint32(_at, Endian.little);
    _at += 4;
    return value;
  }

  Uint8List _bytes(int length) {
    if (_at + length > _data.length) {
      throw const WireFormatException('truncated frame: value runs past the end');
    }
    // Copy, so the returned slice does not pin the whole frame alive.
    final value = Uint8List.fromList(_data.sublist(_at, _at + length));
    _at += length;
    return value;
  }

  MapEntry<int, Uint8List> field() {
    final tag = _u32();
    return MapEntry(tag, _bytes(_u32()));
  }

  StoredRecord record() {
    final kind = RecordKind.fromCode(_u32());
    final key = utf8.decode(_bytes(_u32()));
    final length = _u32();
    if (length == _tombstone) {
      return StoredRecord(kind, key, null);
    }
    return StoredRecord(kind, key, _bytes(length));
  }

  /// Read the whole frame as fields.
  Map<int, Uint8List> fields() {
    final out = <int, Uint8List>{};
    for (var i = 0; i < count; i++) {
      final entry = field();
      out[entry.key] = entry.value;
    }
    return out;
  }

  /// Read the whole frame as records.
  List<StoredRecord> records() =>
      List.generate(count, (_) => record(), growable: false);
}

Uint8List _u32(int value) =>
    Uint8List(4)..buffer.asByteData().setUint32(0, value, Endian.little);

int readU32(Uint8List value) {
  if (value.length != 4) {
    throw WireFormatException(
      'expected a 4-byte number, got ${value.length} bytes',
    );
  }
  return ByteData.sublistView(value).getUint32(0, Endian.little);
}
