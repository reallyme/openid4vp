// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_verifier::{BrowserSessionBinding, SessionRecord};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{ResponseCode, RuntimeError, VerifiedAuthorizationResponse};

/// Fixed-size opaque lease identifier chosen by the durable store.
pub const SESSION_RESERVATION_ID_BYTES: usize = 32;

/// Exclusive lease over one live verifier session.
///
/// The store constructs this value only after atomically transitioning the
/// session from `live` to `reserved`. The runtime returns the same opaque id on
/// release or commit so a stale worker cannot mutate a newer reservation.
pub struct SessionReservation {
    session: SessionRecord,
    reservation_id: [u8; SESSION_RESERVATION_ID_BYTES],
}

impl SessionReservation {
    /// Construct a store-issued reservation.
    ///
    /// This constructor is for durable store adapters. Reservation ids must be
    /// unpredictable and unique within the lifetime of the session key.
    pub const fn new(
        session: SessionRecord,
        reservation_id: [u8; SESSION_RESERVATION_ID_BYTES],
    ) -> Self {
        Self {
            session,
            reservation_id,
        }
    }

    /// Borrow the exact immutable session held by this lease.
    #[must_use]
    pub const fn session(&self) -> &SessionRecord {
        &self.session
    }

    /// Borrow the opaque id for adapter-side compare-and-swap operations.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; SESSION_RESERVATION_ID_BYTES] {
        &self.reservation_id
    }
}

impl fmt::Debug for SessionReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionReservation")
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for SessionReservation {
    fn zeroize(&mut self) {
        self.session.zeroize();
        self.reservation_id.zeroize();
    }
}

impl Drop for SessionReservation {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for SessionReservation {}

/// Atomic verifier authorization state store.
///
/// A conforming adapter implements a durable state machine:
/// `live -> reserved -> committed`. `release_session` is the sole transition
/// from `reserved` back to `live`. `commit_verified_authorization_response`
/// must persist the consumed state, immutable verified result, and response
/// code in one transaction. When the session carries a follow-back requirement,
/// the committed result remains pending and MUST NOT be returned by any result
/// lookup until `redeem_follow_back` succeeds. An error from commit MUST mean
/// that no part of the commit became visible, so the runtime can release and
/// safely retry.
pub trait VerifierSessionStore: Send + Sync {
    /// Load a verifier session for non-authorizing inspection.
    fn load_session(&self, key: &str) -> Result<SessionRecord, RuntimeError>;

    /// Atomically reserve a live session for one response attempt.
    fn reserve_session(&self, key: &str) -> Result<SessionReservation, RuntimeError>;

    /// Release the exact reservation after decryption or validation failure.
    fn release_session(
        &self,
        key: &str,
        reservation: &SessionReservation,
    ) -> Result<(), RuntimeError>;

    /// Atomically consume the reservation and persist the verified result.
    fn commit_verified_authorization_response(
        &self,
        key: &str,
        reservation: &SessionReservation,
        response_code: &ResponseCode,
        result: VerifiedAuthorizationResponse<'_>,
    ) -> Result<(), RuntimeError>;

    /// Atomically release one pending result after same-device follow-back.
    ///
    /// The adapter compares `browser_session` in constant time with the value
    /// retained in the committed session, checks the deadline against
    /// `now_unix`, and performs exactly one `pending -> releasable` transition.
    /// Mismatch, expiry, and replay must return their corresponding typed
    /// runtime reasons without exposing or deleting the pending result.
    fn redeem_follow_back(
        &self,
        response_code: &ResponseCode,
        browser_session: &BrowserSessionBinding,
        now_unix: u64,
    ) -> Result<(), RuntimeError>;
}
