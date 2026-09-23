// Measures what a message actually costs through this binding, so the numbers in
// the README are measured rather than assumed.
//
//   dart run example/benchmark.dart
//
// The interesting figure is not the raw crypto — Signal's Rust does that in tens
// of microseconds — but the crossing: every call copies the plaintext into
// native memory and copies the ciphertext back out.

import 'dart:convert';
import 'dart:io';

import 'package:libsignal_dart/libsignal_dart.dart';

const int _messages = 5000;

void main() {
  final name = Platform.isWindows
      ? 'libsignal_dart.dll'
      : Platform.isMacOS
          ? 'liblibsignal_dart.dylib'
          : 'liblibsignal_dart.so';
  SignalSession.loadLibraryFrom('${Directory.current.path}/native/target/release/$name');

  final aliceIdentity = SignalSession.generateIdentity();
  final bobIdentity = SignalSession.generateIdentity();
  final alice = SignalSession.open(
    identity: aliceIdentity,
    name: 'alice',
    deviceId: 1,
  );
  final bob = SignalSession.open(
    identity: bobIdentity,
    name: 'bob',
    deviceId: 1,
  );

  final signed = bob.generateSignedPreKey(1);
  final kyber = bob.generateKyberPreKey(1);
  final oneTime = bob.generatePreKeys(startId: 1, count: 1).single;
  bob.takeDirty();

  final body = utf8.encode('周末去了趟径山，山顶的茶园刚采完，空气里都是茶味。');

  // --- first message: what a new conversation costs -------------------------
  final establishing = Stopwatch()..start();
  alice.processPreKeyBundle(PreKeyBundle(
    name: 'bob',
    deviceId: 1,
    registrationId: bobIdentity.registrationId,
    identityKey: bob.identityKey,
    signedPreKey: signed,
    kyberPreKey: kyber,
    preKey: oneTime,
  ));
  final opening = alice.encrypt(toName: 'bob', toDeviceId: 1, plaintext: body);
  establishing.stop();
  bob.decrypt(
    fromName: 'alice',
    fromDeviceId: 1,
    type: opening.type,
    ciphertext: opening.ciphertext,
  );

  // Let bob answer so both sides leave the prekey stage.
  final reply = bob.encrypt(toName: 'alice', toDeviceId: 1, plaintext: body);
  alice.decrypt(
    fromName: 'bob',
    fromDeviceId: 1,
    type: reply.type,
    ciphertext: reply.ciphertext,
  );
  alice.takeDirty();
  bob.takeDirty();

  // --- steady state ---------------------------------------------------------
  // Drain after every message, the way an app with a database behind it must.
  final envelopes = <EncryptedMessage>[];
  var dirtyRows = 0;
  var dirtyBytes = 0;
  var firstRow = 0;
  var largestRow = 0;
  final encrypting = Stopwatch()..start();
  for (var i = 0; i < _messages; i++) {
    envelopes.add(alice.encrypt(toName: 'bob', toDeviceId: 1, plaintext: body));
    for (final record in alice.takeDirty()) {
      final size = record.value?.length ?? 0;
      dirtyRows++;
      dirtyBytes += size;
      if (firstRow == 0) firstRow = size;
      if (size > largestRow) largestRow = size;
    }
  }
  encrypting.stop();

  final decrypting = Stopwatch()..start();
  for (final envelope in envelopes) {
    bob.decrypt(
      fromName: 'alice',
      fromDeviceId: 1,
      type: envelope.type,
      ciphertext: envelope.ciphertext,
    );
  }
  decrypting.stop();

  final steady = envelopes.last.ciphertext.length;
  void line(String label, Object value) =>
      stdout.writeln('  ${label.padRight(34)}$value');

  stdout.writeln('libsignal_dart benchmark ($_messages messages)\n');
  line('plaintext', '${body.length} bytes');
  line('first envelope', '${opening.ciphertext.length} bytes');
  line('steady-state envelope', '$steady bytes');
  line('steady-state overhead', '${steady - body.length} bytes');
  line('session setup + first encrypt',
      '${establishing.elapsedMicroseconds} us');
  line('encrypt',
      '${(encrypting.elapsedMicroseconds / _messages).toStringAsFixed(1)} us/msg');
  line('decrypt',
      '${(decrypting.elapsedMicroseconds / _messages).toStringAsFixed(1)} us/msg');
  line('rows written per message',
      '${(dirtyRows / _messages).toStringAsFixed(1)} '
      '(${(dirtyBytes / _messages).round()} bytes)');
  line('pending after draining', '${alice.pendingWrites}');
  line('session row, first vs largest', '$firstRow -> $largestRow bytes');
  line(
    'throughput',
    '${(_messages / (encrypting.elapsedMicroseconds / 1e6)).round()} msg/s encrypt',
  );

  alice.close();
  bob.close();
}

