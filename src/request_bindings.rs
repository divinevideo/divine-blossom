//! Config and credential bindings for one incoming Compute request.
use crate::error::{BlossomError, Result};
use fastly::handle::config_store::ConfigStoreHandle;
use fastly_shared::FastlyStatus;
use fastly_sys::fastly_secret_store;
use std::cell::RefCell;
use std::collections::BTreeMap;

type Binding<T> = std::result::Result<T, &'static str>;
type Value = Binding<Option<String>>;

#[derive(Default)]
struct Bindings {
    configs: BTreeMap<String, Value>,
    secrets: BTreeMap<String, Value>,
    config_store: Option<Binding<ConfigStoreHandle>>,
    secret_store: Option<Binding<u32>>,
    #[cfg(test)]
    reads: [usize; 3],
}

impl Bindings {
    fn config(&mut self, key: &str) -> Value {
        if let Some(value) = self.configs.get(key) {
            return value.clone();
        }
        let value = self.read_config(key);
        self.configs.insert(key.to_owned(), value.clone());
        value
    }

    fn read_config(&mut self, key: &str) -> Value {
        let store = self
            .config_store
            .get_or_insert_with(|| {
                #[allow(deprecated)] // This service targets wasip1.
                ConfigStoreHandle::open("blossom_config")
                    .ok()
                    .filter(|h| h.is_valid())
                    .ok_or("Config store unavailable")
            })
            .as_ref()
            .map_err(|e| *e)?;
        #[cfg(test)]
        {
            self.reads[0] += 1;
        }
        // The entire permitted Config Store value fits in the first ABI call.
        store
            .get(key, 8000 * 4)
            .map_err(|_| "Config lookup unavailable")
    }

    fn secret(&mut self, key: &str) -> Value {
        if let Some(value) = self.secrets.get(key) {
            return value.clone();
        }
        let value = self.read_secret(key);
        self.secrets.insert(key.to_owned(), value.clone());
        value
    }

    fn read_secret(&mut self, key: &str) -> Value {
        let store = self
            .secret_store
            .get_or_insert_with(|| {
                let name = "blossom_secrets";
                let mut handle = fastly_shared::INVALID_SECRET_STORE_HANDLE;
                // SAFETY: the name and output handle stay valid for the synchronous call.
                let status =
                    unsafe { fastly_secret_store::open(name.as_ptr(), name.len(), &mut handle) };
                status
                    .result()
                    .map(|_| handle)
                    .map_err(|_| "Secret store unavailable")
            })
            .as_ref()
            .map_err(|e| *e)?;
        let mut handle = fastly_shared::INVALID_SECRET_HANDLE;
        #[cfg(test)]
        {
            self.reads[1] += 1;
        }
        // SAFETY: the bound store and key are valid throughout this synchronous lookup.
        let status =
            unsafe { fastly_secret_store::get(*store, key.as_ptr(), key.len(), &mut handle) };
        if status == FastlyStatus::NONE {
            return Ok(None);
        }
        status.result().map_err(|_| "Secret lookup unavailable")?;
        // A legal 64 KiB binding takes exactly one plaintext call. The SDK's
        // 1 KiB initial buffer can require another read for larger bindings.
        let mut bytes = vec![0; 64 * 1024];
        let mut written = 0;
        #[cfg(test)]
        {
            self.reads[2] += 1;
        }
        // SAFETY: the writable buffer and length output stay valid for the call.
        let status = unsafe {
            fastly_secret_store::plaintext(handle, bytes.as_mut_ptr(), bytes.len(), &mut written)
        };
        status
            .result()
            .map_err(|_| "Secret plaintext unavailable")?;
        if written > bytes.len() {
            return Err("Invalid secret length");
        }
        bytes.truncate(written);
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| "Invalid secret encoding")
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Bindings>> = const { RefCell::new(None) };
    #[cfg(test)]
    static LAST_READS: std::cell::Cell<[usize; 3]> = const { std::cell::Cell::new([0;3]) };
}

pub(crate) struct RequestScope;

pub(crate) fn begin() -> RequestScope {
    CURRENT.with(|slot| *slot.borrow_mut() = Some(Bindings::default()));
    RequestScope
}

impl Drop for RequestScope {
    fn drop(&mut self) {
        CURRENT.with(|slot| {
            let _bindings = slot.borrow_mut().take();
            #[cfg(test)]
            LAST_READS.set(_bindings.unwrap().reads);
        });
    }
}

fn lookup(operation: impl FnOnce(&mut Bindings) -> Value) -> Result<Option<String>> {
    CURRENT.with(|slot| {
        let mut slot = slot.borrow_mut();
        match slot.as_mut() {
            Some(bindings) => operation(bindings),
            None => operation(&mut Bindings::default()),
        }
        .map_err(|message| BlossomError::Internal(message.into()))
    })
}

pub(crate) fn config(key: &str) -> Result<Option<String>> {
    lookup(|bindings| bindings.config(key))
}

/// The exceptional purge fallback must leave a native read slot for any
/// credential still needed by this execution.
pub(crate) fn can_read_secret(key: &str) -> bool {
    has_secret_budget(&[key])
}

/// Whether `key` has already been loaded in the current request's secret cache.
pub(crate) fn secret_cached(key: &str) -> bool {
    CURRENT.with(|slot| {
        slot.borrow()
            .as_ref()
            .is_some_and(|bindings| bindings.secrets.contains_key(key))
    })
}

/// Whether all distinct `keys` fit inside the 5-secret per-request Compute limit.
pub(crate) fn has_secret_budget(keys: &[&str]) -> bool {
    CURRENT.with(|slot| {
        slot.borrow().as_ref().is_none_or(|bindings| {
            let mut needed = 0usize;
            for (index, key) in keys.iter().enumerate() {
                if !bindings.secrets.contains_key(*key) && !keys[..index].contains(key) {
                    needed += 1;
                }
            }
            bindings.secrets.len() + needed <= 5
        })
    })
}

pub(crate) fn secret(key: &str) -> Result<Option<String>> {
    lookup(|bindings| bindings.secret(key))
}

#[cfg(test)]
pub(crate) fn metered(req: fastly::Request) -> fastly::Response {
    let path = req.get_path().to_owned();
    let phase = if path.starts_with("/api/bunny-playback/") {
        "selection"
    } else {
        path.rsplit('/').next().unwrap()
    };
    let mark = |name: &str| {
        let response = fastly::Request::post("http://fixture.invalid/fixture/meter")
            .with_body(name)
            .send("fixture_control")
            .unwrap();
        assert!(response.get_status().is_success());
    };
    mark(phase);
    let response = crate::handle_main(req).unwrap();
    mark("outside");
    let [config, secrets, plaintext] = LAST_READS.get();
    eprintln!("BUNNY_QUOTA {path} {config} {secrets} {plaintext}");
    assert!((1..=32).contains(&config) && secrets <= 5 && plaintext <= 5,
        "Fastly request limits exceeded: {path} config={config} secrets={secrets} plaintext={plaintext}");
    response
}
