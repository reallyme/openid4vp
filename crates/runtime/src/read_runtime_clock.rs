// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{RuntimeError, RuntimeErrorReason};

/// Runtime clock boundary for verifier HTTP endpoints.
pub trait RuntimeClock: Send + Sync {
    /// Return the current Unix timestamp in seconds.
    fn now_unix(&self) -> Result<u64, RuntimeError>;
}

/// Production clock backed by the host system time.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemRuntimeClock;

impl RuntimeClock for SystemRuntimeClock {
    fn now_unix(&self) -> Result<u64, RuntimeError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| RuntimeError::new(RuntimeErrorReason::ClockUnavailable))?;
        Ok(duration.as_secs())
    }
}
