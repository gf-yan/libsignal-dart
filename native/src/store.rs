//! The protocol store, plus the bookkeeping that lets Dart persist it.
//!
//! libsignal's own stores are in-memory. Rather than push the store traits across
//! the FFI boundary as callbacks — which would drag Dart isolates and async into
//! the middle of the ratchet — this keeps the in-memory store on the Rust side and
//! reports what changed after every operation. Dart writes those rows to SQLCipher
//! and hands them back at startup. The ratchet never waits on Dart.

use std::collections::{BTreeMap, HashMap};
use std::time::SystemTime;

use futures_executor::block_on;
use libsignal_protocol::*;
use rand::rngs::OsRng;
use rand::TryRngCore;

use crate::wire::{self, Writer};

pub const KIND_SESSION: u32 = 1;
pub const KIND_PRE_KEY: u32 = 2;
pub const KIND_SIGNED_PRE_KEY: u32 = 3;
pub const KIND_KYBER_PRE_KEY: u32 = 4;
pub const KIND_IDENTITY: u32 = 5;

// Bundle field tags, mirrored in the Dart encoder.
const TAG_REGISTRATION_ID: u32 = 1;
const TAG_DEVICE_ID: u32 = 2;
const TAG_PRE_KEY_ID: u32 = 3;
const TAG_PRE_KEY_PUBLIC: u32 = 4;
const TAG_SIGNED_PRE_KEY_ID: u32 = 5;
const TAG_SIGNED_PRE_KEY_PUBLIC: u32 = 6;
const TAG_SIGNED_PRE_KEY_SIGNATURE: u32 = 7;
const TAG_KYBER_PRE_KEY_ID: u32 = 8;
const TAG_KYBER_PRE_KEY_PUBLIC: u32 = 9;
const TAG_KYBER_PRE_KEY_SIGNATURE: u32 = 10;
const TAG_IDENTITY_KEY: u32 = 11;
/// The owner's name. Not part of libsignal's bundle, but needed to build the
/// address the bundle belongs to.
const TAG_NAME: u32 = 12;

/// The separator between a name and a device id in a storage key. A control
/// character, so it cannot collide with a UUID or a username.
const ADDRESS_SEPARATOR: char = '\u{1}';

pub struct Store {
    inner: InMemSignalProtocolStore,
    local: ProtocolAddress,
    /// Pending writes, keyed so that repeated changes to the same row collapse
    /// into one. A session record is rewritten on every message; without this the
    /// list would grow without bound whenever Dart is slow to drain it.
    /// `None` is a deletion.
    dirty: BTreeMap<(u32, String), Option<Vec<u8>>>,
    /// What Dart has already been told about, so unchanged rows are not rewritten.
    persisted_identities: HashMap<String, Vec<u8>>,
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub fn address_key(address: &ProtocolAddress) -> String {
    format!(
        "{}{}{}",
        address.name(),
        ADDRESS_SEPARATOR,
        u32::from(address.device_id())
    )
}

pub fn parse_address(key: &str) -> Result<ProtocolAddress, String> {
    let (name, device) = key
        .split_once(ADDRESS_SEPARATOR)
        .ok_or_else(|| format!("malformed address key: {key:?}"))?;
    let device: u32 = device
        .parse()
        .map_err(|_| format!("malformed device id in {key:?}"))?;
    make_address(name, device)
}

pub fn make_address(name: &str, device_id: u32) -> Result<ProtocolAddress, String> {
    let narrowed: u8 = device_id
        .try_into()
        .map_err(|_| format!("device id {device_id} is outside 1..=127"))?;
    let narrowed = DeviceId::new(narrowed)
        .map_err(|_| format!("device id {device_id} is outside 1..=127"))?;
    Ok(ProtocolAddress::new(name.to_string(), narrowed))
}

impl Store {
    pub fn new(
        identity: &[u8],
        registration_id: u32,
        local_name: &str,
        local_device_id: u32,
    ) -> Result<Self, String> {
        let identity = IdentityKeyPair::try_from(identity)
            .map_err(|e| format!("identity key pair is not readable: {e}"))?;
        let inner = InMemSignalProtocolStore::new(identity, registration_id)
            .map_err(|e| format!("cannot create store: {e}"))?;
        Ok(Self {
            inner,
            local: make_address(local_name, local_device_id)?,
            dirty: BTreeMap::new(),
            persisted_identities: HashMap::new(),
        })
    }

    /// Put a row that Dart already had on disk back into the store. Loading is not
    /// a change, so nothing is marked dirty.
    pub fn load(&mut self, kind: u32, key: &str, value: &[u8]) -> Result<(), String> {
        match kind {
            KIND_SESSION => {
                let address = parse_address(key)?;
                let record = SessionRecord::deserialize(value)
                    .map_err(|e| format!("session record for {key:?} is not readable: {e}"))?;
                block_on(self.inner.store_session(&address, &record))
                    .map_err(|e| format!("cannot load session {key:?}: {e}"))?;
            }
            KIND_PRE_KEY => {
                let id: PreKeyId = parse_id(key)?.into();
                let record = PreKeyRecord::deserialize(value)
                    .map_err(|e| format!("prekey {key} is not readable: {e}"))?;
                block_on(self.inner.save_pre_key(id, &record))
                    .map_err(|e| format!("cannot load prekey {key}: {e}"))?;
            }
            KIND_SIGNED_PRE_KEY => {
                let id: SignedPreKeyId = parse_id(key)?.into();
                let record = SignedPreKeyRecord::deserialize(value)
                    .map_err(|e| format!("signed prekey {key} is not readable: {e}"))?;
                block_on(self.inner.save_signed_pre_key(id, &record))
                    .map_err(|e| format!("cannot load signed prekey {key}: {e}"))?;
            }
            KIND_KYBER_PRE_KEY => {
                let id: KyberPreKeyId = parse_id(key)?.into();
                let record = KyberPreKeyRecord::deserialize(value)
                    .map_err(|e| format!("kyber prekey {key} is not readable: {e}"))?;
                block_on(self.inner.save_kyber_pre_key(id, &record))
                    .map_err(|e| format!("cannot load kyber prekey {key}: {e}"))?;
            }
            KIND_IDENTITY => {
                let address = parse_address(key)?;
                let identity = IdentityKey::decode(value)
                    .map_err(|e| format!("identity for {key:?} is not readable: {e}"))?;
                block_on(self.inner.save_identity(&address, &identity))
                    .map_err(|e| format!("cannot load identity {key:?}: {e}"))?;
                self.persisted_identities
                    .insert(key.to_string(), value.to_vec());
            }
            other => return Err(format!("unknown record kind {other}")),
        }
        Ok(())
    }

    /// The public identity key, for upload to the key directory.
    pub fn identity_public(&self) -> Result<Vec<u8>, String> {
        let pair = block_on(self.inner.get_identity_key_pair())
            .map_err(|e| format!("cannot read identity: {e}"))?;
        Ok(pair.identity_key().serialize().to_vec())
    }

    /// Generate one-time prekeys. Returns a record list of `id -> public key` for
    /// upload; the private halves stay in the store and are reported as dirty.
    pub fn generate_pre_keys(&mut self, start_id: u32, count: u32) -> Result<Vec<u8>, String> {
        let mut rng = OsRng.unwrap_err();
        let mut published = Writer::new();
        for offset in 0..count {
            let id = start_id
                .checked_add(offset)
                .ok_or("prekey id overflowed u32")?;
            let pre_key_id: PreKeyId = id.into();
            let pair = KeyPair::generate(&mut rng);
            let record = PreKeyRecord::new(pre_key_id, &pair);
            block_on(self.inner.save_pre_key(pre_key_id, &record))
                .map_err(|e| format!("cannot save prekey {id}: {e}"))?;
            let serialized = record
                .serialize()
                .map_err(|e| format!("cannot serialize prekey {id}: {e}"))?;
            self.put_dirty(KIND_PRE_KEY, id.to_string(), serialized);
            published.record(
                KIND_PRE_KEY,
                id.to_string().as_bytes(),
                Some(&pair.public_key.serialize()),
            );
        }
        Ok(published.finish())
    }

    /// Generate a signed prekey. Returns its id, public key and signature.
    pub fn generate_signed_pre_key(&mut self, id: u32) -> Result<Vec<u8>, String> {
        let mut rng = OsRng.unwrap_err();
        let identity = block_on(self.inner.get_identity_key_pair())
            .map_err(|e| format!("cannot read identity: {e}"))?;
        let pair = KeyPair::generate(&mut rng);
        let signature = identity
            .private_key()
            .calculate_signature(&pair.public_key.serialize(), &mut rng)
            .map_err(|e| format!("cannot sign the signed prekey: {e}"))?;
        let signed_id: SignedPreKeyId = id.into();
        let record = SignedPreKeyRecord::new(
            signed_id,
            Timestamp::from_epoch_millis(now_millis()),
            &pair,
            &signature,
        );
        block_on(self.inner.save_signed_pre_key(signed_id, &record))
            .map_err(|e| format!("cannot save signed prekey {id}: {e}"))?;
        let serialized = record
            .serialize()
            .map_err(|e| format!("cannot serialize signed prekey {id}: {e}"))?;
        self.put_dirty(KIND_SIGNED_PRE_KEY, id.to_string(), serialized);

        let mut published = Writer::new();
        published.field_u32(TAG_SIGNED_PRE_KEY_ID, id);
        published.field(TAG_SIGNED_PRE_KEY_PUBLIC, &pair.public_key.serialize());
        published.field(TAG_SIGNED_PRE_KEY_SIGNATURE, &signature);
        Ok(published.finish())
    }

    /// Generate a Kyber1024 prekey. Post-quantum, and required by the bundle.
    pub fn generate_kyber_pre_key(&mut self, id: u32) -> Result<Vec<u8>, String> {
        let mut rng = OsRng.unwrap_err();
        let identity = block_on(self.inner.get_identity_key_pair())
            .map_err(|e| format!("cannot read identity: {e}"))?;
        let pair = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
        let signature = identity
            .private_key()
            .calculate_signature(&pair.public_key.serialize(), &mut rng)
            .map_err(|e| format!("cannot sign the kyber prekey: {e}"))?;
        let kyber_id: KyberPreKeyId = id.into();
        let record = KyberPreKeyRecord::new(
            kyber_id,
            Timestamp::from_epoch_millis(now_millis()),
            &pair,
            &signature,
        );
        block_on(self.inner.save_kyber_pre_key(kyber_id, &record))
            .map_err(|e| format!("cannot save kyber prekey {id}: {e}"))?;
        let serialized = record
            .serialize()
            .map_err(|e| format!("cannot serialize kyber prekey {id}: {e}"))?;
        self.put_dirty(KIND_KYBER_PRE_KEY, id.to_string(), serialized);

        let mut published = Writer::new();
        published.field_u32(TAG_KYBER_PRE_KEY_ID, id);
        published.field(TAG_KYBER_PRE_KEY_PUBLIC, &pair.public_key.serialize());
        published.field(TAG_KYBER_PRE_KEY_SIGNATURE, &signature);
        Ok(published.finish())
    }

    /// Start a session from a bundle fetched out of the server's key directory.
    pub fn process_pre_key_bundle(&mut self, bundle: &[u8]) -> Result<(), String> {
        let mut rng = OsRng.unwrap_err();
        let (address, bundle) = decode_bundle(bundle)?;
        let local = self.local.clone();
        block_on(process_prekey_bundle(
            &address,
            &local,
            &mut self.inner.session_store,
            &mut self.inner.identity_store,
            &bundle,
            SystemTime::now(),
            &mut rng,
        ))
        .map_err(|e| format!("cannot start a session with {address}: {e}"))?;
        self.capture(&address)?;
        Ok(())
    }

    /// Encrypt one message for one device. Returns `(message type, ciphertext)`.
    pub fn encrypt(
        &mut self,
        name: &str,
        device_id: u32,
        plaintext: &[u8],
    ) -> Result<(u32, Vec<u8>), String> {
        let mut rng = OsRng.unwrap_err();
        let address = make_address(name, device_id)?;
        let local = self.local.clone();
        let message = block_on(message_encrypt(
            plaintext,
            &address,
            &local,
            &mut self.inner.session_store,
            &mut self.inner.identity_store,
            SystemTime::now(),
            &mut rng,
        ))
        .map_err(|e| format!("cannot encrypt for {address}: {e}"))?;
        self.capture(&address)?;
        Ok((message.message_type() as u32, message.serialize().to_vec()))
    }

    /// Decrypt one message from one device.
    pub fn decrypt(
        &mut self,
        name: &str,
        device_id: u32,
        message_type: u32,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, String> {
        let mut rng = OsRng.unwrap_err();
        let address = make_address(name, device_id)?;
        let local = self.local.clone();

        let (message, consumed_pre_key) = if message_type == CiphertextMessageType::PreKey as u32 {
            let message = PreKeySignalMessage::try_from(ciphertext)
                .map_err(|e| format!("cannot read the prekey message: {e}"))?;
            let consumed = message.pre_key_id();
            (CiphertextMessage::PreKeySignalMessage(message), consumed)
        } else if message_type == CiphertextMessageType::Whisper as u32 {
            let message = SignalMessage::try_from(ciphertext)
                .map_err(|e| format!("cannot read the message: {e}"))?;
            (CiphertextMessage::SignalMessage(message), None)
        } else {
            return Err(format!("unsupported message type {message_type}"));
        };

        let store = &mut self.inner;
        let plaintext = block_on(message_decrypt(
            &message,
            &address,
            &local,
            &mut store.session_store,
            &mut store.identity_store,
            &mut store.pre_key_store,
            &store.signed_pre_key_store,
            &mut store.kyber_pre_key_store,
            &mut rng,
        ))
        .map_err(|e| format!("cannot decrypt from {address}: {e}"))?;

        // A one-time prekey is consumed exactly once. Tell Dart to drop the row so
        // a restore from backup cannot resurrect a spent key.
        if let Some(id) = consumed_pre_key {
            let id = u32::from(id);
            if block_on(self.inner.get_pre_key(id.into())).is_err() {
                self.delete_dirty(KIND_PRE_KEY, id.to_string());
            }
        }
        self.capture(&address)?;
        Ok(plaintext)
    }

    /// Whether we hold a session with this device that can still send.
    ///
    /// "Usable" here means not stale and established with PQXDH. Every bundle this
    /// app publishes carries a Kyber prekey, so an X3DH-only session can only mean
    /// a downgrade, and the right answer is to fetch a fresh bundle. SPQR is
    /// deliberately not required: libsignal warns that a peer downgrade can turn a
    /// session that passed the check into one that fails it.
    pub fn has_session(&self, name: &str, device_id: u32) -> Result<bool, String> {
        let address = make_address(name, device_id)?;
        let record = block_on(self.inner.load_session(&address))
            .map_err(|e| format!("cannot read the session with {address}: {e}"))?;
        match record {
            Some(record) => record
                .has_usable_sender_chain(
                    SystemTime::now(),
                    SessionUsabilityRequirements::NotStale
                        | SessionUsabilityRequirements::EstablishedWithPqxdh,
                )
                .map_err(|e| format!("cannot inspect the session with {address}: {e}")),
            None => Ok(false),
        }
    }

    /// Whether this identity key is the one already trusted for this device.
    /// `false` for a *changed* key is what raises the safety-number banner.
    pub fn is_trusted(&self, name: &str, device_id: u32, identity: &[u8]) -> Result<bool, String> {
        let address = make_address(name, device_id)?;
        let identity = IdentityKey::decode(identity)
            .map_err(|e| format!("identity key is not readable: {e}"))?;
        block_on(
            self.inner
                .is_trusted_identity(&address, &identity, Direction::Sending),
        )
        .map_err(|e| format!("cannot check the identity of {address}: {e}"))
    }

    /// Everything Dart must write since the last call. Draining means each row is
    /// handed over once, so Dart must commit them before asking again.
    pub fn take_dirty(&mut self) -> Vec<u8> {
        let mut writer = Writer::new();
        for ((kind, key), value) in std::mem::take(&mut self.dirty) {
            writer.record(kind, key.as_bytes(), value.as_deref());
        }
        writer.finish()
    }

    /// How many rows are waiting to be written. Only useful for diagnostics.
    pub fn pending(&self) -> usize {
        self.dirty.len()
    }

    fn put_dirty(&mut self, kind: u32, key: String, value: Vec<u8>) {
        self.dirty.insert((kind, key), Some(value));
    }

    fn delete_dirty(&mut self, kind: u32, key: String) {
        self.dirty.insert((kind, key), None);
    }

    /// Record the session and identity for an address after an operation touched it.
    fn capture(&mut self, address: &ProtocolAddress) -> Result<(), String> {
        let key = address_key(address);
        if let Some(record) = block_on(self.inner.load_session(address))
            .map_err(|e| format!("cannot read back the session with {address}: {e}"))?
        {
            let serialized = record
                .serialize()
                .map_err(|e| format!("cannot serialize the session with {address}: {e}"))?;
            self.put_dirty(KIND_SESSION, key.clone(), serialized);
        }
        if let Some(identity) = block_on(self.inner.get_identity(address))
            .map_err(|e| format!("cannot read back the identity of {address}: {e}"))?
        {
            let serialized = identity.serialize().to_vec();
            if self.persisted_identities.get(&key) != Some(&serialized) {
                self.persisted_identities
                    .insert(key.clone(), serialized.clone());
                self.put_dirty(KIND_IDENTITY, key, serialized);
            }
        }
        Ok(())
    }
}

fn parse_id(key: &str) -> Result<u32, String> {
    key.parse()
        .map_err(|_| format!("expected a numeric key, got {key:?}"))
}

fn decode_bundle(data: &[u8]) -> Result<(ProtocolAddress, PreKeyBundle), String> {
    let mut registration_id = None;
    let mut device_id = None;
    let mut name: Option<&[u8]> = None;
    let mut pre_key_id = None;
    let mut pre_key_public = None;
    let mut signed_id = None;
    let mut signed_public = None;
    let mut signed_signature = None;
    let mut kyber_id = None;
    let mut kyber_public = None;
    let mut kyber_signature = None;
    let mut identity_key = None;

    for (tag, value) in wire::fields(data)? {
        match tag {
            TAG_REGISTRATION_ID => registration_id = Some(wire::u32_field(value)?),
            TAG_DEVICE_ID => device_id = Some(wire::u32_field(value)?),
            TAG_PRE_KEY_ID => pre_key_id = Some(wire::u32_field(value)?),
            TAG_PRE_KEY_PUBLIC => pre_key_public = Some(value),
            TAG_SIGNED_PRE_KEY_ID => signed_id = Some(wire::u32_field(value)?),
            TAG_SIGNED_PRE_KEY_PUBLIC => signed_public = Some(value),
            TAG_SIGNED_PRE_KEY_SIGNATURE => signed_signature = Some(value),
            TAG_KYBER_PRE_KEY_ID => kyber_id = Some(wire::u32_field(value)?),
            TAG_KYBER_PRE_KEY_PUBLIC => kyber_public = Some(value),
            TAG_KYBER_PRE_KEY_SIGNATURE => kyber_signature = Some(value),
            TAG_IDENTITY_KEY => identity_key = Some(value),
            TAG_NAME => name = Some(value),
            _ => {} // forward compatible: ignore tags this version does not know
        }
    }

    let missing = |what: &str| format!("prekey bundle is missing {what}");
    let name = std::str::from_utf8(name.ok_or_else(|| missing("the owner name"))?)
        .map_err(|_| "owner name is not valid UTF-8".to_string())?;
    let device_id = device_id.ok_or_else(|| missing("the device id"))?;
    let address = make_address(name, device_id)?;

    let one_time = match (pre_key_id, pre_key_public) {
        (Some(id), Some(public)) => Some((
            PreKeyId::from(id),
            PublicKey::deserialize(public)
                .map_err(|e| format!("prekey public key is not readable: {e}"))?,
        )),
        // The directory may be out of one-time prekeys. The session still forms,
        // with weaker forward secrecy for the first message.
        _ => None,
    };

    let bundle = PreKeyBundle::new(
        registration_id.ok_or_else(|| missing("the registration id"))?,
        address.device_id(),
        one_time,
        SignedPreKeyId::from(signed_id.ok_or_else(|| missing("the signed prekey id"))?),
        PublicKey::deserialize(signed_public.ok_or_else(|| missing("the signed prekey"))?)
            .map_err(|e| format!("signed prekey is not readable: {e}"))?,
        signed_signature
            .ok_or_else(|| missing("the signed prekey signature"))?
            .to_vec(),
        KyberPreKeyId::from(kyber_id.ok_or_else(|| missing("the kyber prekey id"))?),
        kem::PublicKey::deserialize(kyber_public.ok_or_else(|| missing("the kyber prekey"))?)
            .map_err(|e| format!("kyber prekey is not readable: {e}"))?,
        kyber_signature
            .ok_or_else(|| missing("the kyber prekey signature"))?
            .to_vec(),
        IdentityKey::decode(identity_key.ok_or_else(|| missing("the identity key"))?)
            .map_err(|e| format!("identity key is not readable: {e}"))?,
    )
    .map_err(|e| format!("prekey bundle is not usable: {e}"))?;

    Ok((address, bundle))
}
