// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use core::fmt;

use reallyme_openid4vp_types::{AuthorizationRequestObject, RequestUriMethod, ResponseMode};
use reallyme_openid4vp_verifier::{
    validate_jar_claims, FollowBackRequirement, JarPolicy, PostResponseRedirectUri, RequestBinding,
    RetainedMdocSessionTranscript, SessionRecord,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::handle_verifier_proto::request_binding_from_authorization_request;
use crate::{
    HostedRequestObject, RuntimeError, RuntimeErrorReason, VerifierEvidenceContext,
    VerifierRuntimeService,
};

/// Request for launching an OpenID4VP authorization flow through a hosted
/// Request Object.
#[derive(Clone, PartialEq)]
pub struct AuthorizationRequestLaunchRequest {
    /// Wallet authorization endpoint, for example the OIDF mock wallet endpoint.
    pub authorization_endpoint: String,
    /// Final OpenID4VP Authorization Request Object to sign and host.
    pub authorization_request: AuthorizationRequestObject,
    /// Adapter-defined verifier session key used by the direct-post endpoint.
    pub session_key: String,
    /// Adapter-defined hosted Request Object key used by the request_uri endpoint.
    pub request_object_key: String,
    /// Absolute request_uri that resolves to the hosted Request Object endpoint.
    pub request_uri: String,
    /// Request URI retrieval method advertised to the wallet.
    pub request_uri_method: RequestUriMethod,
    /// Optional OIDF evidence identity committed atomically with launch material.
    pub evidence_context: Option<VerifierEvidenceContext>,
    /// Exact mdoc SessionTranscript built from this request's handover inputs.
    pub mdoc_session_transcript: Option<RetainedMdocSessionTranscript>,
    /// HTTPS destination returned after successful direct-post processing.
    pub post_response_redirect_uri: Option<PostResponseRedirectUri>,
    /// Initiating browser-session receipt required for HAIP same-device follow-back.
    pub follow_back_requirement: Option<FollowBackRequirement>,
}

impl fmt::Debug for AuthorizationRequestLaunchRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequestLaunchRequest")
            .field("request_uri_method", &self.request_uri_method)
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for AuthorizationRequestLaunchRequest {
    fn zeroize(&mut self) {
        self.authorization_endpoint.zeroize();
        self.authorization_request.zeroize();
        self.session_key.zeroize();
        self.request_object_key.zeroize();
        self.request_uri.zeroize();
        self.evidence_context.zeroize();
        self.mdoc_session_transcript.zeroize();
        self.post_response_redirect_uri.zeroize();
        self.follow_back_requirement.zeroize();
    }
}

impl Drop for AuthorizationRequestLaunchRequest {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AuthorizationRequestLaunchRequest {}

/// Stored launch material supplied atomically to the service host.
#[derive(Clone, PartialEq)]
pub struct AuthorizationRequestLaunchStoreRecord<'a> {
    /// Adapter-defined verifier session key.
    pub session_key: &'a str,
    /// Session record used later for response validation.
    pub session: SessionRecord,
    /// Adapter-defined hosted Request Object key.
    pub request_object_key: &'a str,
    /// Hosted compact Request Object JWT and request_uri POST nonce policy.
    pub request_object: HostedRequestObject,
    /// Optional OIDF evidence identity for both lookup keys.
    pub evidence_context: Option<VerifierEvidenceContext>,
}

impl fmt::Debug for AuthorizationRequestLaunchStoreRecord<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequestLaunchStoreRecord")
            .field("session", &"<redacted>")
            .field("request_object", &"<redacted>")
            .field("lookup_keys", &"<redacted>")
            .finish()
    }
}

/// Host storage boundary for verifier launch material.
///
/// The session and hosted Request Object should be committed together. A
/// response without a stored session fails validation, and a request_uri without
/// a stored object strands the wallet before consent.
pub trait AuthorizationRequestLaunchStore: Send + Sync {
    /// Store all material needed to complete one verifier authorization flow.
    fn store_authorization_request_launch(
        &self,
        record: AuthorizationRequestLaunchStoreRecord<'_>,
    ) -> Result<(), RuntimeError>;
}

/// Authorization endpoint parameter name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizationRequestParameterName {
    /// `client_id`.
    ClientId,
    /// `request_uri`.
    RequestUri,
    /// `request_uri_method`.
    RequestUriMethod,
}

impl AuthorizationRequestParameterName {
    /// Return the OpenID4VP authorization endpoint parameter name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientId => "client_id",
            Self::RequestUri => "request_uri",
            Self::RequestUriMethod => "request_uri_method",
        }
    }
}

/// Authorization endpoint parameter returned to a service host.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationRequestParameter {
    /// Strong parameter name.
    pub name: AuthorizationRequestParameterName,
    /// Parameter value.
    pub value: String,
}

impl fmt::Debug for AuthorizationRequestParameter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequestParameter")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Zeroize for AuthorizationRequestParameter {
    fn zeroize(&mut self) {
        self.value.zeroize();
    }
}

impl Drop for AuthorizationRequestParameter {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AuthorizationRequestParameter {}

/// Launch material ready for the host to send to the wallet authorization
/// endpoint.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizationRequestLaunch {
    /// Wallet authorization endpoint.
    pub authorization_endpoint: String,
    /// Form/query parameters for the authorization endpoint.
    pub parameters: Vec<AuthorizationRequestParameter>,
}

impl fmt::Debug for AuthorizationRequestLaunch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizationRequestLaunch")
            .field("parameter_count", &self.parameters.len())
            .field("values", &"<redacted>")
            .finish()
    }
}

impl Zeroize for AuthorizationRequestLaunch {
    fn zeroize(&mut self) {
        self.authorization_endpoint.zeroize();
        self.parameters.zeroize();
    }
}

impl Drop for AuthorizationRequestLaunch {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for AuthorizationRequestLaunch {}

impl VerifierRuntimeService {
    /// Prepare, store, and return authorization endpoint parameters for a
    /// verifier request_uri flow.
    ///
    /// GET Request Objects are signed immediately. POST Request Objects are
    /// stored as validated templates because the wallet nonce can only be
    /// bound after the wallet submits it to `request_uri`.
    pub fn prepare_authorization_request_launch(
        &self,
        request: &AuthorizationRequestLaunchRequest,
        store: &dyn AuthorizationRequestLaunchStore,
        now_unix: u64,
    ) -> Result<AuthorizationRequestLaunch, RuntimeError> {
        validate_launch_request(request, now_unix)?;
        let response_mode = direct_post_response_mode(&request.authorization_request)?;
        let Some(signer) = self.signer() else {
            return Err(RuntimeError::new(RuntimeErrorReason::MissingSigner));
        };
        validate_jar_claims(
            &request.authorization_request,
            now_unix,
            JarPolicy::default(),
        )
        .map_err(|_| RuntimeError::new(RuntimeErrorReason::SigningFailed))?;
        let binding = request_binding_from_authorization_request(&request.authorization_request)?;
        let session = session_from_request(
            &request.authorization_request,
            binding,
            response_mode,
            request.mdoc_session_transcript.clone(),
            request.post_response_redirect_uri.clone(),
            request.follow_back_requirement.clone(),
        );
        let request_object = match request.request_uri_method {
            RequestUriMethod::Get => {
                let jwt = signer
                    .sign_request_object(&request.authorization_request)
                    .map_err(|_| RuntimeError::new(RuntimeErrorReason::SigningFailed))?;
                HostedRequestObject::signed(jwt)
            }
            RequestUriMethod::Post => {
                HostedRequestObject::deferred_post(request.authorization_request.clone())?
            }
        };
        store.store_authorization_request_launch(AuthorizationRequestLaunchStoreRecord {
            session_key: &request.session_key,
            session,
            request_object_key: &request.request_object_key,
            request_object,
            evidence_context: request.evidence_context.clone(),
        })?;
        Ok(AuthorizationRequestLaunch {
            authorization_endpoint: request.authorization_endpoint.clone(),
            parameters: authorization_endpoint_parameters(request)?,
        })
    }
}

fn validate_launch_request(
    request: &AuthorizationRequestLaunchRequest,
    now_unix: u64,
) -> Result<(), RuntimeError> {
    if request.authorization_endpoint.is_empty()
        || request.session_key.is_empty()
        || request.request_object_key.is_empty()
        || request.request_uri.is_empty()
    {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    }
    if request.authorization_request.wallet_nonce.is_some() {
        return Err(RuntimeError::new(RuntimeErrorReason::WalletNonceMismatch));
    }
    match (
        request.post_response_redirect_uri.as_ref(),
        request.follow_back_requirement.as_ref(),
    ) {
        (Some(_), Some(requirement)) => {
            if requirement.expires_unix() <= now_unix
                || request
                    .authorization_request
                    .exp
                    .is_some_and(|request_expiry| requirement.expires_unix() > request_expiry)
            {
                return Err(RuntimeError::new(
                    RuntimeErrorReason::InvalidFollowBackRequirement,
                ));
            }
        }
        (None, None) => {}
        (Some(_), None) | (None, Some(_)) => {
            return Err(RuntimeError::new(
                RuntimeErrorReason::InvalidFollowBackRequirement,
            ));
        }
    }
    Ok(())
}

fn session_from_request(
    request: &AuthorizationRequestObject,
    binding: RequestBinding,
    response_mode: ResponseMode,
    mdoc_session_transcript: Option<RetainedMdocSessionTranscript>,
    post_response_redirect_uri: Option<PostResponseRedirectUri>,
    follow_back_requirement: Option<FollowBackRequirement>,
) -> SessionRecord {
    SessionRecord {
        binding,
        state: request.state.clone(),
        dcql_query: request.dcql_query.clone(),
        response_mode,
        mdoc_session_transcript,
        post_response_redirect_uri,
        follow_back_requirement,
    }
}

fn direct_post_response_mode(
    request: &AuthorizationRequestObject,
) -> Result<ResponseMode, RuntimeError> {
    match request.response_mode {
        Some(mode @ (ResponseMode::DirectPost | ResponseMode::DirectPostJwt)) => Ok(mode),
        Some(
            ResponseMode::Fragment
            | ResponseMode::FormPost
            | ResponseMode::DcApi
            | ResponseMode::DcApiJwt,
        )
        | None => Err(RuntimeError::new(RuntimeErrorReason::UnsupportedFeature)),
    }
}

fn authorization_endpoint_parameters(
    request: &AuthorizationRequestLaunchRequest,
) -> Result<Vec<AuthorizationRequestParameter>, RuntimeError> {
    let Some(client_id) = request.authorization_request.client_id.as_ref() else {
        return Err(RuntimeError::new(RuntimeErrorReason::MissingField));
    };
    let mut parameters = vec![
        AuthorizationRequestParameter {
            name: AuthorizationRequestParameterName::ClientId,
            value: client_id.to_wire_value(),
        },
        AuthorizationRequestParameter {
            name: AuthorizationRequestParameterName::RequestUri,
            value: request.request_uri.clone(),
        },
    ];
    if request.request_uri_method == RequestUriMethod::Post {
        parameters.push(AuthorizationRequestParameter {
            name: AuthorizationRequestParameterName::RequestUriMethod,
            value: "post".to_owned(),
        });
    }
    Ok(parameters)
}

#[cfg(test)]
#[path = "prepare_authorization_request_launch_tests.rs"]
mod tests;
