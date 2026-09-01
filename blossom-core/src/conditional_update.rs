use serde::de::DeserializeOwned;
use serde::Serialize;
use std::time::Duration;

pub enum ConditionalJsonMutation<T, R> {
    Complete(R),
    Write {
        value: T,
        result: R,
        time_to_live: Option<Duration>,
    },
}

/// Run a JSON read-modify-write loop against generation-aware storage.
///
/// `write` returns `false` for a precondition failure, which causes the whole
/// mutation to re-read current state and retry.
pub fn update_json_conditionally_with_io<T, R, F, L, W>(
    max_attempts: usize,
    operation: &str,
    mut mutate: F,
    mut lookup: L,
    mut write: W,
) -> Result<R, String>
where
    T: DeserializeOwned + Serialize,
    F: FnMut(Option<T>) -> Result<ConditionalJsonMutation<T, R>, String>,
    L: FnMut() -> Result<Option<(String, u64)>, String>,
    W: FnMut(String, Option<u64>, Option<Duration>) -> Result<bool, String>,
{
    for _ in 0..max_attempts {
        let current = lookup()?
            .map(|(value, generation)| {
                serde_json::from_str(&value)
                    .map(|value| (value, generation))
                    .map_err(|error| format!("Failed to parse {operation}: {error}"))
            })
            .transpose()?;
        let generation = current.as_ref().map(|(_, generation)| *generation);
        match mutate(current.map(|(value, _)| value))? {
            ConditionalJsonMutation::Complete(result) => return Ok(result),
            ConditionalJsonMutation::Write {
                value,
                result,
                time_to_live,
            } => {
                let value = serde_json::to_string(&value)
                    .map_err(|error| format!("Failed to serialize {operation}: {error}"))?;
                if write(value, generation, time_to_live)? {
                    return Ok(result);
                }
            }
        }
    }

    Err(format!("{operation} changed too many times"))
}

#[cfg(test)]
mod tests {
    use super::{update_json_conditionally_with_io, ConditionalJsonMutation};
    use std::cell::{Cell, RefCell};
    use std::time::Duration;

    #[test]
    fn retries_precondition_failures_and_preserves_ttl() {
        let ttl = Duration::from_secs(1);
        let lookups = Cell::new(0);
        let writes = Cell::new(0);
        let observed_ttls = RefCell::new(Vec::new());

        let result = update_json_conditionally_with_io(
            3,
            "test list update",
            |current: Option<Vec<String>>| {
                let mut hashes = current.expect("test value should exist");
                hashes.clear();
                Ok(ConditionalJsonMutation::Write {
                    value: hashes,
                    result: true,
                    time_to_live: Some(ttl),
                })
            },
            || {
                let generation = lookups.get() as u64 + 1;
                lookups.set(lookups.get() + 1);
                Ok(Some((r#"["hash"]"#.to_string(), generation)))
            },
            |_, _, observed_ttl| {
                observed_ttls.borrow_mut().push(observed_ttl);
                writes.set(writes.get() + 1);
                Ok(writes.get() > 1)
            },
        )
        .expect("second generation-matched write should commit");

        assert!(result);
        assert_eq!(lookups.get(), 2);
        assert_eq!(writes.get(), 2);
        assert_eq!(*observed_ttls.borrow(), vec![Some(ttl), Some(ttl)]);
    }

    #[test]
    fn reports_retry_exhaustion() {
        let error = update_json_conditionally_with_io(
            2,
            "test update",
            |current: Option<Vec<String>>| {
                Ok(ConditionalJsonMutation::Write {
                    value: current.unwrap_or_default(),
                    result: (),
                    time_to_live: None,
                })
            },
            || Ok(Some(("[]".to_string(), 1))),
            |_, _, _| Ok(false),
        )
        .expect_err("repeated precondition failures should exhaust retries");

        assert!(error.contains("test update changed too many times"));
    }
}
