use std::time::Duration;

use rand::RngExt;

/// Capped exponential backoff with jitter. The hub sends no `Retry-After`.
#[derive(Clone, Debug)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub base: Duration,
    pub cap: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 6,
            base: Duration::from_millis(250),
            cap: Duration::from_secs(10),
        }
    }
}

impl RetryPolicy {
    /// Half fixed, half random: never zero, never synchronised.
    pub fn delay(&self, attempt: u32) -> Duration {
        let exp = self
            .base
            .saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX));
        let half = exp.min(self.cap) / 2;
        let jitter_ms = rand::rng().random_range(0..=half.as_millis() as u64);
        half + Duration::from_millis(jitter_ms)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The status is an answer; the caller interprets it.
    Answer,
    /// "Not now": 429, 408, 5xx. Never an answer.
    Retry,
    /// The session died: authenticate again.
    Reauth,
}

pub fn classify(status: u16) -> Verdict {
    match status {
        401 => Verdict::Reauth,
        408 | 429 | 500..=599 => Verdict::Retry,
        _ => Verdict::Answer,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_statuses_retry_and_401_reauths() {
        for s in [408, 429, 500, 502, 503, 504] {
            assert_eq!(classify(s), Verdict::Retry, "{s}");
        }
        assert_eq!(classify(401), Verdict::Reauth);
        for s in [200, 201, 204, 400, 403, 404, 409, 422] {
            assert_eq!(classify(s), Verdict::Answer, "{s}");
        }
    }

    #[test]
    fn delay_grows_and_is_capped() {
        let p = RetryPolicy::default();
        for attempt in 0..40 {
            let d = p.delay(attempt);
            assert!(d <= p.cap);
            assert!(d > Duration::ZERO);
        }
        assert!(p.delay(0) <= Duration::from_millis(250));
        assert!(p.delay(30) >= p.cap / 2);
    }
}
