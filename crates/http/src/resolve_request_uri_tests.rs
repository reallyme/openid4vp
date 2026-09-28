// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

#![allow(clippy::expect_used)]

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};

use reallyme_openid4vp_types::{
    CanonicalEndpointHost, RequestUriMethod, REQUEST_OBJECT_MEDIA_TYPE,
};
use reallyme_openid4vp_wallet::AuthorizationRequestTransport;

use crate::build_request_uri_http_request::REQUEST_URI_POST_CONTENT_TYPE;
use crate::error::{HttpAdapterError, HttpAdapterErrorReason};
use crate::resolve_request_uri::{
    resolve_request_uri_transport, RequestObjectHttpResponse, RequestUriFetchConstraints,
    RequestUriFetcher, RequestUriHttpRequest, RequestUriNetworkPolicy, RequestUriResolutionPolicy,
};

const VALID_COMPACT_JWS: &str = "c2lnbmVk.cmVxdWVzdA.and0";
const VALID_COMPACT_JWE: &str = "eyJhbGciOiJFQ0RILUVTIn0..aXY.Y2lwaGVy.dGFn";

macro_rules! resolve_to_public_fixture_ip {
    () => {
        fn resolve_request_uri_host(
            &self,
            _host: &CanonicalEndpointHost,
        ) -> Result<Vec<IpAddr>, HttpAdapterError> {
            Ok(vec!["93.184.216.34"
                .parse::<IpAddr>()
                .expect("fixture public IP parses")])
        }
    };
}

fn response(jwt: &str) -> RequestObjectHttpResponse {
    RequestObjectHttpResponse::new(
        200,
        REQUEST_OBJECT_MEDIA_TYPE.to_owned(),
        jwt.to_owned(),
        "93.184.216.34"
            .parse::<IpAddr>()
            .expect("fixture public IP parses"),
        0,
    )
}

struct FixtureFetcher;

impl RequestUriFetcher for FixtureFetcher {
    resolve_to_public_fixture_ip!();

    fn fetch_request_object(
        &self,
        uri: &str,
        request: &RequestUriHttpRequest,
        constraints: RequestUriFetchConstraints<'_>,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
        if uri == "https://verifier.example/request.jwt"
            && request.accept == REQUEST_OBJECT_MEDIA_TYPE
            && request.content_type == Some(REQUEST_URI_POST_CONTENT_TYPE)
            && request.body == b"wallet_nonce=0123456789abcdef"
            && constraints.max_response_bytes >= VALID_COMPACT_JWS.len()
            && !constraints.allow_redirects
            && constraints.resolved_ips
                == ["93.184.216.34"
                    .parse::<IpAddr>()
                    .expect("fixture public IP parses")]
        {
            return Ok(response(VALID_COMPACT_JWS));
        }
        Err(HttpAdapterError::new(
            HttpAdapterErrorReason::RequestUriFetchFailed,
        ))
    }
}

struct PostWithoutOptionalParametersFetcher;

impl RequestUriFetcher for PostWithoutOptionalParametersFetcher {
    resolve_to_public_fixture_ip!();

    fn fetch_request_object(
        &self,
        uri: &str,
        request: &RequestUriHttpRequest,
        _constraints: RequestUriFetchConstraints<'_>,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
        if uri == "https://verifier.example/request.jwt"
            && request.accept == REQUEST_OBJECT_MEDIA_TYPE
            && request.content_type == Some(REQUEST_URI_POST_CONTENT_TYPE)
            && request.body.is_empty()
        {
            return Ok(response(VALID_COMPACT_JWS));
        }
        Err(HttpAdapterError::new(
            HttpAdapterErrorReason::RequestUriFetchFailed,
        ))
    }
}

#[test]
fn resolves_request_uri_transport_to_request_jwt() {
    let resolved = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://verifier.example/request.jwt".to_owned(),
            method: RequestUriMethod::Post,
            wallet_nonce: Some("0123456789abcdef".to_owned()),
            expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
        },
        &FixtureFetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect("fixture request_uri resolves");

    assert_eq!(
        resolved,
        AuthorizationRequestTransport::RequestJwt {
            jwt: VALID_COMPACT_JWS.to_owned(),
            expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
            expected_wallet_nonce: Some("0123456789abcdef".to_owned()),
        }
    );
}

#[test]
fn resolves_post_request_uri_without_optional_wallet_nonce() {
    let resolved = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://verifier.example/request.jwt".to_owned(),
            method: RequestUriMethod::Post,
            wallet_nonce: None,
            expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
        },
        &PostWithoutOptionalParametersFetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect("POST request_uri resolves without optional parameters");

    assert_eq!(
        resolved,
        AuthorizationRequestTransport::RequestJwt {
            jwt: VALID_COMPACT_JWS.to_owned(),
            expected_client_id: Some("x509_san_dns:verifier.example".to_owned()),
            expected_wallet_nonce: None,
        }
    );
}

#[test]
fn rejects_non_https_request_uri_by_default() {
    let err = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "http://verifier.example/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &FixtureFetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect_err("non-HTTPS request_uri is rejected");

    assert_eq!(err.reason(), HttpAdapterErrorReason::RequestUriMustBeHttps);
}

#[test]
fn rejects_loopback_request_uri_before_fetch() {
    let err = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://127.0.0.1/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &FixtureFetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect_err("loopback request_uri is rejected");

    assert_eq!(err.reason(), HttpAdapterErrorReason::UnsafeRequestUri);
}

#[test]
fn rejects_metadata_ip_request_uri_before_fetch() {
    let err = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://169.254.169.254/latest/meta-data".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &FixtureFetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect_err("metadata IP request_uri is rejected");

    assert_eq!(err.reason(), HttpAdapterErrorReason::UnsafeRequestUri);
}

#[test]
fn rejects_localhost_request_uri_before_fetch() {
    let err = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://localhost/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &FixtureFetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect_err("localhost request_uri is rejected");

    assert_eq!(err.reason(), HttpAdapterErrorReason::UnsafeRequestUri);
}

#[test]
fn rejects_localhost_subdomain_request_uri_before_resolution() {
    let err = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://foo.localhost/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &FixtureFetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect_err("the entire localhost special-use suffix is rejected");

    assert_eq!(err.reason(), HttpAdapterErrorReason::UnsafeRequestUri);
}

struct LoopbackFetcher;

impl RequestUriFetcher for LoopbackFetcher {
    fn resolve_request_uri_host(
        &self,
        _host: &CanonicalEndpointHost,
    ) -> Result<Vec<IpAddr>, HttpAdapterError> {
        Ok(vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)])
    }

    fn fetch_request_object(
        &self,
        uri: &str,
        _request: &RequestUriHttpRequest,
        constraints: RequestUriFetchConstraints<'_>,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
        if uri == "https://localhost/request.jwt"
            && constraints.resolved_ips == [IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)]
        {
            return Ok(RequestObjectHttpResponse::new(
                200,
                REQUEST_OBJECT_MEDIA_TYPE.to_owned(),
                VALID_COMPACT_JWS.to_owned(),
                IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                0,
            ));
        }
        Err(HttpAdapterError::new(
            HttpAdapterErrorReason::RequestUriFetchFailed,
        ))
    }
}

#[test]
fn loopback_only_policy_accepts_only_a_loopback_request_uri() {
    let policy = RequestUriResolutionPolicy::default()
        .with_network_policy(RequestUriNetworkPolicy::LoopbackOnly);
    let resolved = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://localhost/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &LoopbackFetcher,
        policy.clone(),
    )
    .expect("explicit loopback policy resolves localhost");
    assert!(matches!(
        resolved,
        AuthorizationRequestTransport::RequestJwt { .. }
    ));

    let public_error = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://verifier.example/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &FixtureFetcher,
        policy,
    )
    .expect_err("loopback policy rejects public destinations");
    assert_eq!(
        public_error.reason(),
        HttpAdapterErrorReason::UnsafeRequestUri
    );
}

#[test]
fn rejects_noncanonical_and_reserved_ssrf_bypass_vectors() {
    let unsafe_uris = [
        "https://127.0.0.1\\.evil.com/",
        "https://2130706433/",
        "https://0x7f.1/",
        "https://127.1/",
        "https://127.0.0.1./",
        "https://%31%32%37.0.0.1/",
        "https://[::ffff:127.0.0.1]/",
        "https://[::ffff:a9fe:a9fe]/",
        "https://localhost./",
        "https://100.64.0.1/",
    ];

    for uri in unsafe_uris {
        let error = resolve_request_uri_transport(
            AuthorizationRequestTransport::RequestUri {
                uri: uri.to_owned(),
                method: RequestUriMethod::Get,
                wallet_nonce: None,
                expected_client_id: None,
            },
            &FixtureFetcher,
            RequestUriResolutionPolicy::default(),
        )
        .expect_err("SSRF bypass vector must be rejected before fetch");
        assert_eq!(error.reason(), HttpAdapterErrorReason::UnsafeRequestUri);
    }
}

struct PrivateDnsAnswerFetcher {
    fetch_called: AtomicBool,
}

impl RequestUriFetcher for PrivateDnsAnswerFetcher {
    fn resolve_request_uri_host(
        &self,
        _host: &CanonicalEndpointHost,
    ) -> Result<Vec<IpAddr>, HttpAdapterError> {
        Ok(vec!["10.0.0.1"
            .parse::<IpAddr>()
            .expect("fixture private IP parses")])
    }

    fn fetch_request_object(
        &self,
        _uri: &str,
        _request: &RequestUriHttpRequest,
        _constraints: RequestUriFetchConstraints<'_>,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
        self.fetch_called.store(true, Ordering::SeqCst);
        Ok(response(VALID_COMPACT_JWS))
    }
}

#[test]
fn rejects_private_dns_answers_before_sending_http_request() {
    let fetcher = PrivateDnsAnswerFetcher {
        fetch_called: AtomicBool::new(false),
    };
    let error = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://verifier.example/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &fetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect_err("private DNS answers must be rejected before fetch");

    assert_eq!(error.reason(), HttpAdapterErrorReason::UnsafeRequestUri);
    assert!(!fetcher.fetch_called.load(Ordering::SeqCst));
}

struct UnsafeIpv6DnsAnswerFetcher {
    address: IpAddr,
    fetch_called: AtomicBool,
}

impl RequestUriFetcher for UnsafeIpv6DnsAnswerFetcher {
    fn resolve_request_uri_host(
        &self,
        _host: &CanonicalEndpointHost,
    ) -> Result<Vec<IpAddr>, HttpAdapterError> {
        Ok(vec![self.address])
    }

    fn fetch_request_object(
        &self,
        _uri: &str,
        _request: &RequestUriHttpRequest,
        _constraints: RequestUriFetchConstraints<'_>,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
        self.fetch_called.store(true, Ordering::SeqCst);
        Ok(response(VALID_COMPACT_JWS))
    }
}

#[test]
fn rejects_ipv6_transition_destinations_from_dns() {
    for address in ["2001:0000::1", "2002:5db8:d822::1"] {
        let fetcher = UnsafeIpv6DnsAnswerFetcher {
            address: address.parse().expect("fixture IPv6 address parses"),
            fetch_called: AtomicBool::new(false),
        };
        let error = resolve_request_uri_transport(
            AuthorizationRequestTransport::RequestUri {
                uri: "https://verifier.example/request.jwt".to_owned(),
                method: RequestUriMethod::Get,
                wallet_nonce: None,
                expected_client_id: None,
            },
            &fetcher,
            RequestUriResolutionPolicy::default(),
        )
        .expect_err("Teredo and 6to4 destinations are never HTTP fetch targets");
        assert_eq!(error.reason(), HttpAdapterErrorReason::UnsafeRequestUri);
        assert!(!fetcher.fetch_called.load(Ordering::SeqCst));
    }
}

struct MismatchedConnectedPeerFetcher;

impl RequestUriFetcher for MismatchedConnectedPeerFetcher {
    resolve_to_public_fixture_ip!();

    fn fetch_request_object(
        &self,
        _uri: &str,
        _request: &RequestUriHttpRequest,
        _constraints: RequestUriFetchConstraints<'_>,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
        Ok(RequestObjectHttpResponse::new(
            200,
            REQUEST_OBJECT_MEDIA_TYPE.to_owned(),
            VALID_COMPACT_JWS.to_owned(),
            "2002:5db8:d822::1"
                .parse::<IpAddr>()
                .expect("fixture 6to4 address parses"),
            0,
        ))
    }
}

#[test]
fn rejects_connected_peer_outside_the_approved_dns_set() {
    let error = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://verifier.example/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &MismatchedConnectedPeerFetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect_err("the transport must attest the exact connected peer");
    assert_eq!(error.reason(), HttpAdapterErrorReason::UnsafeRequestUri);
}

#[test]
fn rejects_non_request_uri_transport() {
    let err = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestJwt {
            jwt: VALID_COMPACT_JWS.to_owned(),
            expected_client_id: None,
            expected_wallet_nonce: None,
        },
        &FixtureFetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect_err("resolver only accepts request_uri transport");

    assert_eq!(err.reason(), HttpAdapterErrorReason::RequestUriRequired);
}

struct EmptyJwtFetcher;

impl RequestUriFetcher for EmptyJwtFetcher {
    resolve_to_public_fixture_ip!();

    fn fetch_request_object(
        &self,
        _uri: &str,
        _request: &RequestUriHttpRequest,
        _constraints: RequestUriFetchConstraints<'_>,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
        Ok(response(""))
    }
}

#[test]
fn rejects_empty_fetched_request_object() {
    let err = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://verifier.example/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &EmptyJwtFetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect_err("empty fetched request object is rejected");

    assert_eq!(
        err.reason(),
        HttpAdapterErrorReason::InvalidRequestObjectEncoding
    );
}

struct MalformedJwtFetcher;

impl RequestUriFetcher for MalformedJwtFetcher {
    resolve_to_public_fixture_ip!();

    fn fetch_request_object(
        &self,
        _uri: &str,
        _request: &RequestUriHttpRequest,
        _constraints: RequestUriFetchConstraints<'_>,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
        Ok(response("header.payload"))
    }
}

#[test]
fn rejects_malformed_fetched_request_object() {
    let err = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://verifier.example/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &MalformedJwtFetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect_err("fetched Request Object must be compact JWS or JWE");

    assert_eq!(
        err.reason(),
        HttpAdapterErrorReason::InvalidRequestObjectEncoding
    );
}

struct EncryptedJwtFetcher;

impl RequestUriFetcher for EncryptedJwtFetcher {
    resolve_to_public_fixture_ip!();

    fn fetch_request_object(
        &self,
        _uri: &str,
        _request: &RequestUriHttpRequest,
        _constraints: RequestUriFetchConstraints<'_>,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
        Ok(response(VALID_COMPACT_JWE))
    }
}

#[test]
fn resolves_encrypted_request_uri_transport_to_request_jwt() {
    let resolved = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://verifier.example/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &EncryptedJwtFetcher,
        RequestUriResolutionPolicy::default(),
    )
    .expect("encrypted fetched Request Object is accepted before JOSE");

    assert_eq!(
        resolved,
        AuthorizationRequestTransport::RequestJwt {
            jwt: VALID_COMPACT_JWE.to_owned(),
            expected_client_id: None,
            expected_wallet_nonce: None,
        }
    );
}

struct LargeJwtFetcher;

impl RequestUriFetcher for LargeJwtFetcher {
    resolve_to_public_fixture_ip!();

    fn fetch_request_object(
        &self,
        _uri: &str,
        _request: &RequestUriHttpRequest,
        _constraints: RequestUriFetchConstraints<'_>,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
        Ok(response(VALID_COMPACT_JWS))
    }
}

#[test]
fn rejects_oversized_fetched_request_object() {
    let err = resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://verifier.example/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        &LargeJwtFetcher,
        RequestUriResolutionPolicy {
            max_request_jwt_bytes: 4,
            post_wallet_nonce: None,
            network_policy: RequestUriNetworkPolicy::PublicOnly,
        },
    )
    .expect_err("oversized fetched request object is rejected");

    assert_eq!(err.reason(), HttpAdapterErrorReason::RequestObjectTooLarge);
}

struct ResponseMetadataFetcher {
    status: u16,
    media_type: &'static str,
}

impl RequestUriFetcher for ResponseMetadataFetcher {
    resolve_to_public_fixture_ip!();

    fn fetch_request_object(
        &self,
        _uri: &str,
        _request: &RequestUriHttpRequest,
        _constraints: RequestUriFetchConstraints<'_>,
    ) -> Result<RequestObjectHttpResponse, HttpAdapterError> {
        Ok(RequestObjectHttpResponse::new(
            self.status,
            self.media_type.to_owned(),
            VALID_COMPACT_JWS.to_owned(),
            "93.184.216.34"
                .parse::<IpAddr>()
                .expect("fixture public IP parses"),
            0,
        ))
    }
}

fn resolve_with_response_metadata(
    fetcher: &ResponseMetadataFetcher,
) -> Result<AuthorizationRequestTransport, HttpAdapterError> {
    resolve_request_uri_transport(
        AuthorizationRequestTransport::RequestUri {
            uri: "https://verifier.example/request.jwt".to_owned(),
            method: RequestUriMethod::Get,
            wallet_nonce: None,
            expected_client_id: None,
        },
        fetcher,
        RequestUriResolutionPolicy::default(),
    )
}

#[test]
fn validates_request_object_http_status_and_media_type_before_jose() {
    resolve_with_response_metadata(&ResponseMetadataFetcher {
        status: 200,
        media_type: "Application/OAuth-Authz-Req+JWT; charset=utf-8",
    })
    .expect("media type comparison is case-insensitive and accepts one parameter");

    for status in [199, 500] {
        let error = resolve_with_response_metadata(&ResponseMetadataFetcher {
            status,
            media_type: REQUEST_OBJECT_MEDIA_TYPE,
        })
        .expect_err("only an HTTP 200 response can carry a Request Object");
        assert_eq!(
            error.reason(),
            HttpAdapterErrorReason::InvalidRequestObjectHttpStatus
        );
    }

    for media_type in [
        "text/html",
        "application/oauth-authz-req+jwt; charset=utf-8; CHARSET=ascii",
        "application/oauth-authz-req+jwt; malformed",
    ] {
        let error = resolve_with_response_metadata(&ResponseMetadataFetcher {
            status: 200,
            media_type,
        })
        .expect_err("malformed or duplicate media-type parameters fail closed");
        assert_eq!(
            error.reason(),
            HttpAdapterErrorReason::InvalidRequestObjectMediaType
        );
    }
}
