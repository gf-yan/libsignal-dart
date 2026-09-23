import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:libsignal_dart/libsignal_dart.dart';
import 'package:test/test.dart';

/// A device with a database behind it.
///
/// The point of these tests is not that libsignal works — Signal's own test
/// suite covers that. It is that *this binding* carries the state across the FFI
/// boundary intact, and that what [SignalSession.takeDirty] hands back is enough
/// to rebuild a working session from cold storage.
class TestDevice {
  TestDevice(this.name, this.deviceId)
      : identity = SignalSession.generateIdentity() {
    session = SignalSession.open(
      identity: identity,
      name: name,
      deviceId: deviceId,
    );
  }

  final String name;
  final int deviceId;
  final DeviceIdentity identity;
  late SignalSession session;

  /// Stands in for the SQLCipher table, keyed the way a real one would be.
  final Map<String, StoredRecord> database = {};

  int _nextPreKeyId = 1;

  /// Drain the session's pending writes into the database, the way the app must
  /// after every operation.
  int flush() {
    final changes = session.takeDirty();
    for (final change in changes) {
      final key = '${change.kind.name}/${change.key}';
      if (change.isDeletion) {
        database.remove(key);
      } else {
        database[key] = change;
      }
    }
    return changes.length;
  }

  /// Throw the process away and rebuild from disk. This is the test that a
  /// binding has to pass and a spike never does.
  void restart() {
    flush();
    session.close();
    session = SignalSession.open(
      identity: identity,
      name: name,
      deviceId: deviceId,
    )..loadAll(database.values);
  }

  /// Publish what the key directory would hold for this device.
  PreKeyBundle publishBundle({bool withOneTimePreKey = true}) {
    final signed = session.generateSignedPreKey(1);
    final kyber = session.generateKyberPreKey(1);
    PublicPreKey? oneTime;
    if (withOneTimePreKey) {
      oneTime = session
          .generatePreKeys(startId: _nextPreKeyId, count: 1)
          .single;
      _nextPreKeyId++;
    }
    flush();
    return PreKeyBundle(
      name: name,
      deviceId: deviceId,
      registrationId: identity.registrationId,
      identityKey: session.identityKey,
      signedPreKey: signed,
      kyberPreKey: kyber,
      preKey: oneTime,
    );
  }

  void dispose() => session.close();
}

String _nativeLibraryPath() {
  final root = Directory.current.path;
  final name = Platform.isWindows
      ? 'libsignal_dart.dll'
      : Platform.isMacOS
          ? 'liblibsignal_dart.dylib'
          : 'liblibsignal_dart.so';
  return '$root/native/target/release/$name';
}

void main() {
  setUpAll(() {
    final path = _nativeLibraryPath();
    if (!File(path).existsSync()) {
      fail(
        'native library not built. Run: cd native && cargo build --release\n'
        'looked for $path',
      );
    }
    SignalSession.loadLibraryFrom(path);
  });

  test('a fresh identity is usable and distinct each time', () {
    final first = SignalSession.generateIdentity();
    final second = SignalSession.generateIdentity();

    expect(first.keyPair, isNotEmpty);
    expect(first.registrationId, inInclusiveRange(1, 16379));
    expect(first.keyPair, isNot(equals(second.keyPair)));
  });

  test('two devices exchange messages in both directions', () {
    final alice = TestDevice('alice', 1);
    final bob = TestDevice('bob', 1);
    addTearDown(alice.dispose);
    addTearDown(bob.dispose);

    alice.session.processPreKeyBundle(bob.publishBundle());
    alice.flush();

    expect(alice.session.hasSession('bob', 1), isTrue);
    expect(bob.session.hasSession('alice', 1), isFalse,
        reason: 'bob has not heard from alice yet');

    final first = alice.session.encrypt(
      toName: 'bob',
      toDeviceId: 1,
      plaintext: utf8.encode('今晚有人一起看流星吗'),
    );
    alice.flush();
    expect(first.type, CiphertextType.preKey);

    final received = bob.session.decrypt(
      fromName: 'alice',
      fromDeviceId: 1,
      type: first.type,
      ciphertext: first.ciphertext,
    );
    bob.flush();
    expect(utf8.decode(received), '今晚有人一起看流星吗');

    final reply = bob.session.encrypt(
      toName: 'alice',
      toDeviceId: 1,
      plaintext: utf8.encode('我也想去'),
    );
    bob.flush();
    expect(reply.type, CiphertextType.whisper,
        reason: 'the session is established, so this is a ratchet message');

    expect(
      utf8.decode(alice.session.decrypt(
        fromName: 'bob',
        fromDeviceId: 1,
        type: reply.type,
        ciphertext: reply.ciphertext,
      )),
      '我也想去',
    );
  });

  test('a session survives a restart from persisted records', () {
    final alice = TestDevice('alice', 1);
    final bob = TestDevice('bob', 1);
    addTearDown(alice.dispose);
    addTearDown(bob.dispose);

    alice.session.processPreKeyBundle(bob.publishBundle());
    final opening = alice.session.encrypt(
      toName: 'bob',
      toDeviceId: 1,
      plaintext: utf8.encode('hello'),
    );
    alice.flush();
    bob.session.decrypt(
      fromName: 'alice',
      fromDeviceId: 1,
      type: opening.type,
      ciphertext: opening.ciphertext,
    );
    bob.flush();

    // Both sides are killed and rebuilt from nothing but their database rows.
    alice.restart();
    bob.restart();

    expect(alice.session.hasSession('bob', 1), isTrue);
    expect(bob.session.hasSession('alice', 1), isTrue);

    final afterRestart = alice.session.encrypt(
      toName: 'bob',
      toDeviceId: 1,
      plaintext: utf8.encode('still here'),
    );
    alice.flush();
    expect(
      utf8.decode(bob.session.decrypt(
        fromName: 'alice',
        fromDeviceId: 1,
        type: afterRestart.type,
        ciphertext: afterRestart.ciphertext,
      )),
      'still here',
    );
  });

  test('messages that arrive out of order still decrypt, replays do not', () {
    final alice = TestDevice('alice', 1);
    final bob = TestDevice('bob', 1);
    addTearDown(alice.dispose);
    addTearDown(bob.dispose);

    alice.session.processPreKeyBundle(bob.publishBundle());
    final messages = [
      for (final body in ['one', 'two', 'three'])
        alice.session.encrypt(
          toName: 'bob',
          toDeviceId: 1,
          plaintext: utf8.encode(body),
        ),
    ];
    alice.flush();

    Uint8List receive(EncryptedMessage message) {
      final plaintext = bob.session.decrypt(
        fromName: 'alice',
        fromDeviceId: 1,
        type: message.type,
        ciphertext: message.ciphertext,
      );
      bob.flush();
      return plaintext;
    }

    // What a lossy mobile network actually delivers.
    expect(utf8.decode(receive(messages[2])), 'three');
    expect(utf8.decode(receive(messages[0])), 'one');
    expect(utf8.decode(receive(messages[1])), 'two');

    expect(
      () => receive(messages[0]),
      throwsA(isA<SignalException>()),
      reason: 'a message already consumed must not decrypt twice',
    );
  });

  test('one message to a user with three devices is three ciphertexts', () {
    final alice = TestDevice('alice', 1);
    final bobDevices = [
      TestDevice('bob', 1),
      TestDevice('bob', 2),
      TestDevice('bob', 3),
    ];
    addTearDown(alice.dispose);
    for (final device in bobDevices) {
      addTearDown(device.dispose);
    }

    for (final device in bobDevices) {
      alice.session.processPreKeyBundle(device.publishBundle());
    }
    alice.flush();

    final body = utf8.encode('一条消息，三台设备');
    final envelopes = <int, EncryptedMessage>{};
    for (final device in bobDevices) {
      envelopes[device.deviceId] = alice.session.encrypt(
        toName: 'bob',
        toDeviceId: device.deviceId,
        plaintext: body,
      );
    }
    alice.flush();

    // Each device gets different bytes; none can read another's copy.
    final distinct = envelopes.values.map((e) => base64.encode(e.ciphertext));
    expect(distinct.toSet(), hasLength(3));

    for (final device in bobDevices) {
      final envelope = envelopes[device.deviceId]!;
      expect(
        utf8.decode(device.session.decrypt(
          fromName: 'alice',
          fromDeviceId: 1,
          type: envelope.type,
          ciphertext: envelope.ciphertext,
        )),
        '一条消息，三台设备',
      );
    }

    final foreign = envelopes[2]!;
    expect(
      () => bobDevices[0].session.decrypt(
        fromName: 'alice',
        fromDeviceId: 1,
        type: foreign.type,
        ciphertext: foreign.ciphertext,
      ),
      throwsA(isA<SignalException>()),
      reason: "device 1 must not be able to read device 2's copy",
    );
  });

  test('a session still forms when the directory has no one-time prekeys', () {
    final dave = TestDevice('dave', 1);
    final carol = TestDevice('carol', 1);
    addTearDown(dave.dispose);
    addTearDown(carol.dispose);

    dave.session
        .processPreKeyBundle(carol.publishBundle(withOneTimePreKey: false));
    final message = dave.session.encrypt(
      toName: 'carol',
      toDeviceId: 1,
      plaintext: utf8.encode('no one-time prekey left'),
    );
    dave.flush();

    expect(
      utf8.decode(carol.session.decrypt(
        fromName: 'dave',
        fromDeviceId: 1,
        type: message.type,
        ciphertext: message.ciphertext,
      )),
      'no one-time prekey left',
    );
  });

  test('a spent one-time prekey is reported for deletion', () {
    final alice = TestDevice('alice', 1);
    final bob = TestDevice('bob', 1);
    addTearDown(alice.dispose);
    addTearDown(bob.dispose);

    final bundle = bob.publishBundle();
    final spentId = bundle.preKey!.id;
    expect(bob.database, contains('preKey/$spentId'));

    alice.session.processPreKeyBundle(bundle);
    final opening = alice.session.encrypt(
      toName: 'bob',
      toDeviceId: 1,
      plaintext: utf8.encode('hello'),
    );
    alice.flush();

    bob.session.decrypt(
      fromName: 'alice',
      fromDeviceId: 1,
      type: opening.type,
      ciphertext: opening.ciphertext,
    );
    bob.flush();

    expect(
      bob.database,
      isNot(contains('preKey/$spentId')),
      reason: 'a consumed prekey must not survive in the database',
    );
  });

  test('a reinstalled contact is not trusted silently', () {
    final alice = TestDevice('alice', 1);
    final bob = TestDevice('bob', 1);
    addTearDown(alice.dispose);
    addTearDown(bob.dispose);

    alice.session.processPreKeyBundle(bob.publishBundle());
    alice.flush();
    expect(
      alice.session.isTrustedIdentity(
        peerName: 'bob',
        peerDeviceId: 1,
        identityKey: bob.session.identityKey,
      ),
      isTrue,
    );

    // Bob reinstalls: same address, brand new identity key.
    final reinstalled = TestDevice('bob', 1);
    addTearDown(reinstalled.dispose);
    expect(
      alice.session.isTrustedIdentity(
        peerName: 'bob',
        peerDeviceId: 1,
        identityKey: reinstalled.session.identityKey,
      ),
      isFalse,
      reason: 'this is what raises the safety-number banner',
    );
  });

  test('session rows say which peer device they belong to', () {
    final alice = TestDevice('alice', 1);
    final bob = TestDevice('bob', 2);
    addTearDown(alice.dispose);
    addTearDown(bob.dispose);

    alice.session.generatePreKeys(startId: 1, count: 1);
    alice.session.processPreKeyBundle(bob.publishBundle());
    final changes = alice.session.takeDirty();

    final sessions = changes
        .where((record) => record.kind == RecordKind.session)
        .map((record) => record.address)
        .toList();
    expect(sessions, [const SignalAddress('bob', 2)]);
    expect(
      changes
          .firstWhere((record) => record.kind == RecordKind.preKey)
          .address,
      isNull,
      reason: 'a prekey row is keyed by id, not by address',
    );
  });

  test('a closed session refuses to be used', () {
    final device = TestDevice('erin', 1);
    device.session.close();
    expect(device.session.isClosed, isTrue);
    expect(
      () => device.session.identityKey,
      throwsA(isA<SignalException>()),
    );
    device.session.close(); // idempotent
  });
}
