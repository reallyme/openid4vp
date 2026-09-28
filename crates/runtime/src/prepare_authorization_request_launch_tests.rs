// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

use zeroize::Zeroize;

use crate::{
    AuthorizationRequestLaunch, AuthorizationRequestParameter, AuthorizationRequestParameterName,
};

#[test]
fn launch_output_redacts_and_zeroizes_parameter_values() {
    let mut launch = AuthorizationRequestLaunch {
        authorization_endpoint: "https://sensitive.example/authorize".to_owned(),
        parameters: vec![AuthorizationRequestParameter {
            name: AuthorizationRequestParameterName::ClientId,
            value: "sensitive-client-id".to_owned(),
        }],
    };

    let debug = format!("{launch:?}");
    assert!(!debug.contains("sensitive.example"));
    assert!(!debug.contains("sensitive-client-id"));

    launch.zeroize();
    assert!(launch.authorization_endpoint.is_empty());
    assert!(launch
        .parameters
        .iter()
        .all(|parameter| parameter.value.is_empty()));
}
