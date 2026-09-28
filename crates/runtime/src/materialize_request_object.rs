// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use reallyme_openid4vp_verifier::{validate_jar_claims, CompactJwt, JarPolicy};

use crate::serve_request_object::RequestObjectRetrieval;
use crate::{HostedRequestObject, RuntimeError, RuntimeErrorReason, VerifierRuntimeService};

impl VerifierRuntimeService {
    /// Bind retrieval-time inputs and produce the signed Request Object.
    pub(crate) fn materialize_request_object(
        &self,
        hosted: &HostedRequestObject,
        retrieval: &RequestObjectRetrieval,
        now_unix: u64,
    ) -> Result<CompactJwt, RuntimeError> {
        match (hosted, retrieval) {
            (HostedRequestObject::Signed { request_object_jwt }, RequestObjectRetrieval::Get) => {
                Ok(request_object_jwt.clone())
            }
            (
                HostedRequestObject::DeferredPost {
                    authorization_request,
                },
                RequestObjectRetrieval::Post { .. },
            ) => {
                let Some(signer) = self.signer() else {
                    return Err(RuntimeError::new(RuntimeErrorReason::MissingSigner));
                };
                let mut request = authorization_request.clone();
                request.wallet_nonce = retrieval.wallet_nonce().map(str::to_owned);
                validate_jar_claims(&request, now_unix, JarPolicy::default())
                    .map_err(|_| RuntimeError::new(RuntimeErrorReason::SigningFailed))?;
                let jwt = signer
                    .sign_request_object(&request)
                    .map_err(|_| RuntimeError::new(RuntimeErrorReason::SigningFailed))?;
                Ok(jwt)
            }
            (HostedRequestObject::Signed { .. }, RequestObjectRetrieval::Post { .. })
            | (HostedRequestObject::DeferredPost { .. }, RequestObjectRetrieval::Get) => {
                Err(RuntimeError::new(RuntimeErrorReason::InvalidHttpMethod))
            }
        }
    }
}
