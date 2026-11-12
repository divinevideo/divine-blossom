// ABOUTME: Re-reads a value this request just wrote, briefly waiting out eventually consistent reads.
// ABOUTME: Returns the first value found, or None once every scheduled re-read has missed.
use std::time::Duration;

/// Delays between re-reads of a key this request has just written.
/// Bounded so a batch of archive items cannot stall a request for long.
pub const READ_BACK_DELAYS_MS: [u64; 4] = [25, 50, 100, 200];

/// Read once, then re-read after each delay while the read finds nothing.
/// Errors are returned immediately; only a missing value is retried.
pub fn read_back<T, E>(
    mut read: impl FnMut() -> Result<Option<T>, E>,
    delays: &[Duration],
    mut sleep: impl FnMut(Duration),
) -> Result<Option<T>, E> {
    if let Some(value) = read()? {
        return Ok(Some(value));
    }
    for delay in delays {
        sleep(*delay);
        if let Some(value) = read()? {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::read_back;
    use std::cell::RefCell;
    use std::time::Duration;

    fn delays() -> Vec<Duration> {
        [25, 50, 100].map(Duration::from_millis).to_vec()
    }

    #[test]
    fn returns_immediately_when_the_first_read_sees_the_write() {
        let slept = RefCell::new(Vec::new());
        let result = read_back(|| Ok::<_, ()>(Some(7)), &delays(), |d| slept.borrow_mut().push(d));
        assert_eq!(result, Ok(Some(7)));
        assert!(slept.borrow().is_empty());
    }

    #[test]
    fn waits_out_a_lagging_read_until_the_write_appears() {
        let reads = RefCell::new(0);
        let slept = RefCell::new(Vec::new());
        let result = read_back(
            || {
                *reads.borrow_mut() += 1;
                Ok::<_, ()>((*reads.borrow() == 3).then_some("gate"))
            },
            &delays(),
            |d| slept.borrow_mut().push(d),
        );
        assert_eq!(result, Ok(Some("gate")));
        assert_eq!(*reads.borrow(), 3);
        assert_eq!(*slept.borrow(), [25, 50].map(Duration::from_millis).to_vec());
    }

    #[test]
    fn gives_up_after_the_last_delay_and_stops_on_errors() {
        let reads = RefCell::new(0);
        let missing = read_back(
            || {
                *reads.borrow_mut() += 1;
                Ok::<Option<u8>, ()>(None)
            },
            &delays(),
            |_| {},
        );
        assert_eq!(missing, Ok(None));
        assert_eq!(*reads.borrow(), 4);

        let reads = RefCell::new(0);
        let failed = read_back(
            || {
                *reads.borrow_mut() += 1;
                Err::<Option<u8>, _>("unavailable")
            },
            &delays(),
            |_| {},
        );
        assert_eq!(failed, Err("unavailable"));
        assert_eq!(*reads.borrow(), 1);
    }
}
