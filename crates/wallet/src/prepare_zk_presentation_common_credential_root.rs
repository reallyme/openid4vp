// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

fn validate_common_credential_root_query(
    query: &reallyme_openid4vp_dcql::CredentialQuery,
    profile: ZkCommonCredentialRootPersonaMode,
    hash_strategy: ZkCredentialHashAlgorithm,
) -> Result<[RequestedCommonCredentialRootClaim; 2], WalletError> {
    let meta = &query.meta;
    if meta.len() != COMMON_CREDENTIAL_ROOT_META_FIELDS
        || meta.keys().any(|key| {
            !matches!(
                key.as_str(),
                "profile"
                    | "hash_strategy"
                    | "claim_0_name_hash"
                    | "claim_0_value_b64u"
                    | "claim_1_name_hash"
                    | "claim_1_value_b64u"
            )
        })
        || meta.get("profile").and_then(serde_json::Value::as_str) != Some(profile.as_str())
        || meta
            .get("hash_strategy")
            .and_then(serde_json::Value::as_str)
            != Some(hash_strategy.as_str())
    {
        return Err(zk_error());
    }
    Ok([
        validate_common_credential_root_claim_meta(meta, "claim_0_name_hash", "claim_0_value_b64u")?,
        validate_common_credential_root_claim_meta(meta, "claim_1_name_hash", "claim_1_value_b64u")?,
    ])
}
fn validate_common_credential_root_claim_meta(
    meta: &serde_json::Map<String, serde_json::Value>,
    name_key: &str,
    value_key: &str,
) -> Result<RequestedCommonCredentialRootClaim, WalletError> {
    let name = meta
        .get(name_key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(zk_error)?;
    let name_hash = parse_lower_hex_hash(name).ok_or_else(zk_error)?;
    let value = meta
        .get(value_key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(zk_error)?;
    if value.is_empty() || value.len() > 86 {
        return Err(zk_error());
    }
    let decoded = Zeroizing::new(base64url_to_bytes(value).map_err(|_| zk_error())?);
    if decoded.is_empty()
        || decoded.len() > MAX_CLAIM_VALUE_BYTES
        || bytes_to_base64url(&decoded) != value
    {
        return Err(zk_error());
    }
    Ok(RequestedCommonCredentialRootClaim {
        name_hash,
        value: decoded,
    })
}
const fn common_credential_root_presentation_profile(
    profile: ZkCommonCredentialRootPersonaMode,
) -> Result<ZkPresentationProfile, WalletError> {
    match profile {
        ZkCommonCredentialRootPersonaMode::PrivatePersona => {
            Ok(ZkPresentationProfile::CommonCredentialRootPrivatePersonaV1)
        }
        ZkCommonCredentialRootPersonaMode::PublicPersona => {
            Ok(ZkPresentationProfile::CommonCredentialRootPublicPersonaV1)
        }
    }
}
const fn common_credential_root_stage_kind(
    slot: ZkCommonCredentialRootProofSlot,
) -> Result<ZkPresentationStageKind, WalletError> {
    match slot {
        ZkCommonCredentialRootProofSlot::RootAttestation => Ok(ZkPresentationStageKind::RootAttestation),
        ZkCommonCredentialRootProofSlot::RootStatus => Ok(ZkPresentationStageKind::RootStatus),
        ZkCommonCredentialRootProofSlot::Lineage0 => Ok(ZkPresentationStageKind::Lineage0),
        ZkCommonCredentialRootProofSlot::Lineage1 => Ok(ZkPresentationStageKind::Lineage1),
        ZkCommonCredentialRootProofSlot::SelectedClaim0 => Ok(ZkPresentationStageKind::SelectedClaim0),
        ZkCommonCredentialRootProofSlot::SelectedClaim1 => Ok(ZkPresentationStageKind::SelectedClaim1),
        ZkCommonCredentialRootProofSlot::Session => Ok(ZkPresentationStageKind::Session),
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus0 => {
            Ok(ZkPresentationStageKind::IssuerCredentialStatus0)
        }
        ZkCommonCredentialRootProofSlot::IssuerCredentialStatus1 => {
            Ok(ZkPresentationStageKind::IssuerCredentialStatus1)
        }
        _ => Err(zk_error()),
    }
}
