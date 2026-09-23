//! The C ABI that Dart's FFI talks to.
//!
//! Rules this file keeps, because getting them wrong is how FFI code corrupts
//! memory in production rather than in a test:
//!
//!   * Every function returns a status code. Values come back through out
//!     parameters, never as a returned pointer.
//!   * Every buffer handed to Dart was allocated here and must come back to
//!     [`signal_dart_free`]. Dart never frees Rust memory itself.
//!   * Nothing unwinds across the boundary. A panic is caught and turned into
//!     [`STATUS_PANIC`] rather than tearing down the host process.
//!   * The error message for a failed call is held per thread and read with
//!     [`signal_dart_last_error`].

use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::slice;

mod store;
mod wire;

pub use store::Store;

/// The call succeeded.
pub const STATUS_OK: i32 = 0;
/// The call failed; the reason is in [`signal_dart_last_error`].
pub const STATUS_ERROR: i32 = 1;
/// A required pointer was null, or a length was impossible.
pub const STATUS_BAD_ARGUMENT: i32 = 2;
/// Rust panicked. This is a bug in the binding, not a protocol failure.
pub const STATUS_PANIC: i32 = 3;

/// Bumped whenever the ABI changes shape. Dart checks it at load time so a stale
/// bundled library fails loudly instead of reading the wrong bytes.
pub const ABI_VERSION: u32 = 1;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn set_error(message: String) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(message));
}

/// Hand a buffer to Dart. Ownership moves with it; it comes back via
/// [`signal_dart_free`].
unsafe fn emit(bytes: Vec<u8>, out_ptr: *mut *mut u8, out_len: *mut usize) {
    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    *out_ptr = ptr;
    *out_len = len;
}

unsafe fn borrow<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if ptr.is_null() {
        if len == 0 {
            return Ok(&[]);
        }
        return Err(STATUS_BAD_ARGUMENT);
    }
    Ok(slice::from_raw_parts(ptr, len))
}

unsafe fn borrow_str<'a>(ptr: *const u8, len: usize) -> Result<&'a str, i32> {
    let bytes = borrow(ptr, len)?;
    std::str::from_utf8(bytes).map_err(|_| {
        set_error("expected UTF-8 text".into());
        STATUS_ERROR
    })
}

/// Run `body`, turning an `Err` into [`STATUS_ERROR`] and a panic into
/// [`STATUS_PANIC`].
fn guard(body: impl FnOnce() -> Result<(), String>) -> i32 {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(())) => STATUS_OK,
        Ok(Err(message)) => {
            set_error(message);
            STATUS_ERROR
        }
        Err(panic) => {
            let detail = panic
                .downcast_ref::<&str>()
                .map(|s| (*s).to_string())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "unknown panic".to_string());
            set_error(format!("libsignal_dart panicked: {detail}"));
            STATUS_PANIC
        }
    }
}

// ---------------------------------------------------------------- lifecycle

#[no_mangle]
pub extern "C" fn signal_dart_abi_version() -> u32 {
    ABI_VERSION
}

/// Release a buffer produced by any function in this library.
///
/// # Safety
/// `ptr`/`len` must be exactly what a previous call wrote, and must be freed once.
#[no_mangle]
pub unsafe extern "C" fn signal_dart_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() || len == 0 {
        return;
    }
    drop(Box::from_raw(slice::from_raw_parts_mut(ptr, len)));
}

/// Take the message for the most recent failure on this thread. Returns an empty
/// buffer when there is none.
///
/// # Safety
/// Both out parameters must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn signal_dart_last_error(
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out_ptr.is_null() || out_len.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    let message = LAST_ERROR.with(|slot| slot.borrow_mut().take());
    emit(message.unwrap_or_default().into_bytes(), out_ptr, out_len);
    STATUS_OK
}

// ---------------------------------------------------------------- registration

/// Generate a fresh long-term identity key pair and registration id. This is the
/// identity a device keeps for its whole life; losing it means a new safety number
/// for every contact.
///
/// # Safety
/// All out parameters must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn signal_dart_identity_generate(
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
    out_registration_id: *mut u32,
) -> i32 {
    if out_ptr.is_null() || out_len.is_null() || out_registration_id.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    guard(|| {
        use rand::{Rng, TryRngCore};
        let mut rng = rand::rngs::OsRng.unwrap_err();
        let identity = libsignal_protocol::IdentityKeyPair::generate(&mut rng);
        // Registration ids are 14 bits by convention; 0 is reserved.
        let registration_id: u32 = rng.random_range(1..16380);
        *out_registration_id = registration_id;
        emit(identity.serialize().to_vec(), out_ptr, out_len);
        Ok(())
    })
}

/// Create a store around an existing identity.
///
/// # Safety
/// Pointers must be valid for their stated lengths; `out_handle` must be writable.
#[no_mangle]
pub unsafe extern "C" fn signal_dart_store_new(
    identity_ptr: *const u8,
    identity_len: usize,
    registration_id: u32,
    name_ptr: *const u8,
    name_len: usize,
    device_id: u32,
    out_handle: *mut *mut Store,
) -> i32 {
    if out_handle.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    let identity = match borrow(identity_ptr, identity_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let name = match borrow_str(name_ptr, name_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    guard(|| {
        let store = Store::new(identity, registration_id, name, device_id)?;
        *out_handle = Box::into_raw(Box::new(store));
        Ok(())
    })
}

/// Destroy a store. The handle must not be used afterwards.
///
/// # Safety
/// `handle` must come from [`signal_dart_store_new`] and be freed once.
#[no_mangle]
pub unsafe extern "C" fn signal_dart_store_free(handle: *mut Store) {
    if handle.is_null() {
        return;
    }
    drop(Box::from_raw(handle));
}

unsafe fn store_of<'a>(handle: *mut Store) -> Result<&'a mut Store, i32> {
    if handle.is_null() {
        set_error("store handle is null".into());
        return Err(STATUS_BAD_ARGUMENT);
    }
    Ok(&mut *handle)
}

// ---------------------------------------------------------------- persistence

/// Put one persisted row back into the store at startup.
///
/// # Safety
/// `handle` must be live; the pointers must be valid for their lengths.
#[no_mangle]
pub unsafe extern "C" fn signal_dart_store_load(
    handle: *mut Store,
    kind: u32,
    key_ptr: *const u8,
    key_len: usize,
    value_ptr: *const u8,
    value_len: usize,
) -> i32 {
    let store = match store_of(handle) {
        Ok(store) => store,
        Err(status) => return status,
    };
    let key = match borrow_str(key_ptr, key_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let value = match borrow(value_ptr, value_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    guard(|| store.load(kind, key, value))
}

/// Drain everything the store has changed since the last call, as a record list.
/// Dart must commit these rows before calling again.
///
/// # Safety
/// `handle` must be live; both out parameters must be writable.
#[no_mangle]
pub unsafe extern "C" fn signal_dart_store_take_dirty(
    handle: *mut Store,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out_ptr.is_null() || out_len.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    let store = match store_of(handle) {
        Ok(store) => store,
        Err(status) => return status,
    };
    guard(|| {
        emit(store.take_dirty(), out_ptr, out_len);
        Ok(())
    })
}

// ---------------------------------------------------------------- key material

/// The public identity key, for upload to the key directory.
///
/// # Safety
/// `handle` must be live; both out parameters must be writable.
#[no_mangle]
pub unsafe extern "C" fn signal_dart_identity_public(
    handle: *mut Store,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out_ptr.is_null() || out_len.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    let store = match store_of(handle) {
        Ok(store) => store,
        Err(status) => return status,
    };
    guard(|| {
        emit(store.identity_public()?, out_ptr, out_len);
        Ok(())
    })
}

macro_rules! generator {
    ($name:ident, $method:ident, $($arg:ident),*) => {
        /// # Safety
        /// `handle` must be live; both out parameters must be writable.
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            handle: *mut Store,
            $($arg: u32,)*
            out_ptr: *mut *mut u8,
            out_len: *mut usize,
        ) -> i32 {
            if out_ptr.is_null() || out_len.is_null() {
                return STATUS_BAD_ARGUMENT;
            }
            let store = match store_of(handle) {
                Ok(store) => store,
                Err(status) => return status,
            };
            guard(|| {
                let published = store.$method($($arg),*)?;
                emit(published, out_ptr, out_len);
                Ok(())
            })
        }
    };
}

generator!(
    signal_dart_generate_pre_keys,
    generate_pre_keys,
    start_id,
    count
);
generator!(
    signal_dart_generate_signed_pre_key,
    generate_signed_pre_key,
    id
);
generator!(
    signal_dart_generate_kyber_pre_key,
    generate_kyber_pre_key,
    id
);

// ---------------------------------------------------------------- sessions

/// Start a session from a prekey bundle fetched out of the key directory.
///
/// # Safety
/// `handle` must be live; the bundle pointer must be valid for its length.
#[no_mangle]
pub unsafe extern "C" fn signal_dart_process_pre_key_bundle(
    handle: *mut Store,
    bundle_ptr: *const u8,
    bundle_len: usize,
) -> i32 {
    let store = match store_of(handle) {
        Ok(store) => store,
        Err(status) => return status,
    };
    let bundle = match borrow(bundle_ptr, bundle_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    guard(|| store.process_pre_key_bundle(bundle))
}

/// Encrypt one message for one device.
///
/// # Safety
/// `handle` must be live; every pointer must be valid for its stated length.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn signal_dart_encrypt(
    handle: *mut Store,
    name_ptr: *const u8,
    name_len: usize,
    device_id: u32,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
    out_message_type: *mut u32,
) -> i32 {
    if out_ptr.is_null() || out_len.is_null() || out_message_type.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    let store = match store_of(handle) {
        Ok(store) => store,
        Err(status) => return status,
    };
    let name = match borrow_str(name_ptr, name_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let plaintext = match borrow(plaintext_ptr, plaintext_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    guard(|| {
        let (message_type, ciphertext) = store.encrypt(name, device_id, plaintext)?;
        *out_message_type = message_type;
        emit(ciphertext, out_ptr, out_len);
        Ok(())
    })
}

/// Decrypt one message from one device.
///
/// # Safety
/// `handle` must be live; every pointer must be valid for its stated length.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn signal_dart_decrypt(
    handle: *mut Store,
    name_ptr: *const u8,
    name_len: usize,
    device_id: u32,
    message_type: u32,
    ciphertext_ptr: *const u8,
    ciphertext_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    if out_ptr.is_null() || out_len.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    let store = match store_of(handle) {
        Ok(store) => store,
        Err(status) => return status,
    };
    let name = match borrow_str(name_ptr, name_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let ciphertext = match borrow(ciphertext_ptr, ciphertext_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    guard(|| {
        let plaintext = store.decrypt(name, device_id, message_type, ciphertext)?;
        emit(plaintext, out_ptr, out_len);
        Ok(())
    })
}

/// Whether a usable sending session with this device already exists.
///
/// # Safety
/// `handle` must be live; `out_result` must be writable.
#[no_mangle]
pub unsafe extern "C" fn signal_dart_has_session(
    handle: *mut Store,
    name_ptr: *const u8,
    name_len: usize,
    device_id: u32,
    out_result: *mut u8,
) -> i32 {
    if out_result.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    let store = match store_of(handle) {
        Ok(store) => store,
        Err(status) => return status,
    };
    let name = match borrow_str(name_ptr, name_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    guard(|| {
        *out_result = u8::from(store.has_session(name, device_id)?);
        Ok(())
    })
}

/// Whether this identity key is the one already trusted for this device.
///
/// # Safety
/// `handle` must be live; every pointer must be valid for its stated length.
#[no_mangle]
pub unsafe extern "C" fn signal_dart_is_trusted_identity(
    handle: *mut Store,
    name_ptr: *const u8,
    name_len: usize,
    device_id: u32,
    identity_ptr: *const u8,
    identity_len: usize,
    out_result: *mut u8,
) -> i32 {
    if out_result.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    let store = match store_of(handle) {
        Ok(store) => store,
        Err(status) => return status,
    };
    let name = match borrow_str(name_ptr, name_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    let identity = match borrow(identity_ptr, identity_len) {
        Ok(value) => value,
        Err(status) => return status,
    };
    guard(|| {
        *out_result = u8::from(store.is_trusted(name, device_id, identity)?);
        Ok(())
    })
}

/// How many rows are waiting to be written. Diagnostics only: a number that
/// keeps climbing means the caller is not draining
/// [`signal_dart_store_take_dirty`].
///
/// # Safety
/// `handle` must be live; `out_pending` must be writable.
#[no_mangle]
pub unsafe extern "C" fn signal_dart_store_pending(
    handle: *mut Store,
    out_pending: *mut usize,
) -> i32 {
    if out_pending.is_null() {
        return STATUS_BAD_ARGUMENT;
    }
    let store = match store_of(handle) {
        Ok(store) => store,
        Err(status) => return status,
    };
    guard(|| {
        *out_pending = store.pending();
        Ok(())
    })
}
