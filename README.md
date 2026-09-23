# libsignal_dart

Dart bindings for the [Signal protocol](https://signal.org/docs/) — PQXDH key
agreement and the Double Ratchet — built directly on
[libsignal](https://github.com/signalapp/libsignal)'s Rust core.

Signal maintains official bindings for Swift, Java/Kotlin, TypeScript and Rust.
There is none for Dart. This is one: a small C ABI over the `libsignal-protocol`
crate, plus a Dart FFI layer over that. No cryptography is reimplemented here.

## Status

Working and tested on Windows x64. Android, iOS and macOS need their targets
built; the Dart side is platform-independent and the Rust side has no
platform-specific code.

```
$ dart test
00:00 +9: All tests passed!
```

## Licence — read this first

libsignal is **AGPL-3.0-only**, and so is this package. The AGPL's obligations
travel to anything that links it. If you ship a closed-source app built on this,
get a lawyer's answer before you do, not a forum's. Signal also offers
commercial licences; that is the other door.

This is not a footnote. It decides whether your application can stay private.

## Design

libsignal's stores are in-memory and its store traits are async. The obvious
binding — implementing those traits in Dart and calling back across the FFI
boundary — drags Dart isolates and futures into the middle of the ratchet, on
every message.

This does the opposite. The native side owns the protocol state, and after every
operation it reports which rows changed. Dart writes those rows to its own
database and replays them at startup. Nothing calls back into Dart, nothing is
async, and the ratchet never waits on storage.

```dart
final identity = SignalSession.generateIdentity();     // once, at registration
final session = SignalSession.open(
  identity: identity,
  name: myUserId,
  deviceId: 1,
);
session.loadAll(await database.keyMaterial());         // every launch

// Starting a conversation, from a bundle the server handed out.
session.processPreKeyBundle(bundle);

final message = session.encrypt(
  toName: peerId,
  toDeviceId: 1,
  plaintext: utf8.encode('今晚有人一起看流星吗'),
);
await database.persist(session.takeDirty());           // not optional
```

Persisting what `takeDirty()` returns is not optional. The ratchet advances on
every message; state that was not written is a message that cannot be decrypted
after a restart. `pendingWrites` exists so a caller can assert it is draining.

A message to a user with three devices is three `encrypt` calls producing three
different ciphertexts. There is no group ciphertext in this layer.

## Measured

`dart run example/benchmark.dart`, 5000 messages, Windows x64, release build:

| | |
|---|---|
| plaintext | 75 bytes |
| first envelope (per device) | 1824 bytes |
| steady-state envelope | 172 bytes |
| steady-state overhead | 97 bytes |
| encrypt | 52.9 µs/msg |
| decrypt | 31.4 µs/msg |
| session setup + first encrypt | 6.9 ms |
| rows written per message | 1 (4301 bytes) |
| session row over 5000 messages | 4298 → 4301 bytes |
| native library, stripped | 1.87 MB |

Two things worth reading off that table. The first envelope is ~1.8 KB because
key agreement is post-quantum — a Kyber1024 ciphertext travels in it — and that
cost is paid once per device, not per message. And the session row does not grow:
4298 bytes at the first message, 4301 at the five-thousandth. Long conversations
do not accumulate state on disk.

The per-message cost is dominated by the crossing, not the crypto: the same
operations measured inside Rust are 34 µs and 25 µs.

## What is covered

The tests in `test/round_trip_test.dart` assert, against the real library:

- messages in both directions, prekey message then ratchet messages
- **a session rebuilt from persisted rows after both sides restart**
- out-of-order delivery (3, 1, 2), and replay rejected
- one message to three devices: three ciphertexts, none readable by another device
- a session still forms when the directory has run out of one-time prekeys
- a spent one-time prekey is reported for deletion
- a reinstalled contact is not silently trusted — the safety-number case
- a closed session refuses to be used

The restart test is the one that matters. Everything else is libsignal working;
that one is *this binding* working.

## Building

libsignal compiles its protobuf definitions during the build, so **`protoc`
must be on `PATH`** before `cargo` runs. That is the one non-obvious
prerequisite; without it the build fails in `libsignal-protocol`'s `build.rs`
on every platform.

```bash
cd native && cargo build --release
cd .. && dart pub get && dart test
```

The tests look for `native/target/release/`. Elsewhere, set
`LIBSIGNAL_DART_LIBRARY` to the library path, or call
`SignalSession.loadLibraryFrom(path)`.

## Layout

```
native/src/wire.rs      byte format shared with Dart
native/src/store.rs     protocol store + dirty-row tracking
native/src/lib.rs       the C ABI
lib/src/wire.dart       the same byte format, the other side
lib/src/bindings.dart   dart:ffi declarations
lib/libsignal_dart.dart the public API
```

`wire.rs` and `wire.dart` describe the same format and must change together.
`ABI_VERSION` in `lib.rs` is checked when Dart loads the library, so a stale
bundled binary fails loudly instead of reading the wrong bytes.

## Not implemented

Sender keys (group messaging), sealed sender, zkgroup, username hashing, the
Signal service client. This is the message-encryption layer only.
