// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_runtime::{
    HostedRequestObject, RequestObjectStore, ResponseCode, RuntimeClock, RuntimeError,
    RuntimeErrorReason, SessionReservation, VerifiedAuthorizationResponse, VerifierSessionStore,
};
use reallyme_openid4vp_verifier::{BrowserSessionBinding, SessionRecord};

/// Fuzz-local session adapter used to exercise the same public HTTP runtime
/// boundary as a production host. Each fuzz invocation owns a fresh adapter,
/// so returning a clone from `take_session` still preserves single-use scope.
pub(crate) struct FuzzSessionStore {
    session: SessionRecord,
}

impl FuzzSessionStore {
    pub(crate) const fn new(session: SessionRecord) -> Self {
        Self { session }
    }
}

impl VerifierSessionStore for FuzzSessionStore {
    fn load_session(&self, _key: &str) -> Result<SessionRecord, RuntimeError> {
        Ok(self.session.clone())
    }

    fn reserve_session(&self, _key: &str) -> Result<SessionReservation, RuntimeError> {
        Ok(SessionReservation::new(self.session.clone(), [7_u8; 32]))
    }

    fn release_session(
        &self,
        _key: &str,
        _reservation: &SessionReservation,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn commit_verified_authorization_response(
        &self,
        _key: &str,
        _reservation: &SessionReservation,
        _response_code: &ResponseCode,
        _result: VerifiedAuthorizationResponse<'_>,
    ) -> Result<(), RuntimeError> {
        Ok(())
    }

    fn redeem_follow_back(
        &self,
        _response_code: &ResponseCode,
        _browser_session: &BrowserSessionBinding,
        _now_unix: u64,
    ) -> Result<(), RuntimeError> {
        Err(RuntimeError::new(RuntimeErrorReason::UnsupportedFeature))
    }
}

/// Direct-post routing does not access Request Object storage. This rejecting
/// adapter makes an accidental route change fail closed instead of supplying
/// unrelated fixture material.
pub(crate) struct RejectingRequestObjectStore;

impl RequestObjectStore for RejectingRequestObjectStore {
    fn load_request_object(&self, _key: &str) -> Result<HostedRequestObject, RuntimeError> {
        Err(RuntimeError::new(RuntimeErrorReason::MissingField))
    }
}

/// Deterministic clock keeps temporal checks stable across fuzz replays.
pub(crate) struct FixedRuntimeClock {
    now_unix: u64,
}

impl FixedRuntimeClock {
    pub(crate) const fn new(now_unix: u64) -> Self {
        Self { now_unix }
    }
}

impl RuntimeClock for FixedRuntimeClock {
    fn now_unix(&self) -> Result<u64, RuntimeError> {
        Ok(self.now_unix)
    }
}
