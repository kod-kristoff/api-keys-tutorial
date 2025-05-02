use std::io::Write;

use chrono::{DateTime, Utc};
use rand::RngCore;
use sha3::{Digest, digest::DynDigest};
use uuid::Uuid;
use zeroize::Zeroize;

use crate::{
    errors::CreateApiKeyError,
    models::{API_KEY_HASH_SIZE, API_KEY_PREFIX, API_KEY_SECRET_SIZE, ApiKey},
    shared::base32,
};

use super::AuthService;

#[derive(Clone, Debug, serde::Deserialize)]
pub struct CreateApiKeyInput {
    pub organization_id: Uuid,
    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ApiKeyWithToken {
    pub api_key: ApiKey,
    pub token: String,
}

impl AuthService {
    pub async fn create_api_key(
        &self,
        // ctx: RequestContext,
        input: CreateApiKeyInput,
    ) -> Result<ApiKeyWithToken, CreateApiKeyError> {
        let name = input.name.trim().to_string();
        validate_api_key_name(&name)?;

        if let Some(expires_at) = input.expires_at {
            validate_api_key_expires_at(expires_at)?;
        }

        let api_key_with_token = generate_api_key_v1(input.organization_id, name, input.expires_at);
        // self.repo.create_api_key(&api_key_with_token.api_key).await?;

        Ok(api_key_with_token)
    }
}

fn validate_api_key_expires_at(expires_at: DateTime<Utc>) -> Result<(), CreateApiKeyError> {
    if expires_at < Utc::now() {
        Err(CreateApiKeyError::ExpiresAtBeforeNow(expires_at))
    } else {
        Ok(())
    }
}

fn validate_api_key_name(name: &str) -> Result<(), CreateApiKeyError> {
    if name.is_empty() {
        Err(CreateApiKeyError::EmptyName)
    } else {
        Ok(())
    }
}

fn generate_api_key_v1(
    organization_id: Uuid,
    name: String,
    expires_at: Option<DateTime<Utc>>,
) -> ApiKeyWithToken {
    let api_key_id = Uuid::now_v7();
    let version = 1;

    // token_data = [ api_key_id (16 bytes) || secret (32 bytes) ]
    let mut token_data = [0u8; 16 + API_KEY_SECRET_SIZE];
    token_data[..16].copy_from_slice(api_key_id.as_bytes());
    rand::rng().fill_bytes(&mut token_data[16..]);

    let hash = hash_api_key(api_key_id, version, organization_id, &token_data[16..]);

    let mut token = base32::encode_lowercase(&token_data);
    token.insert_str(0, "_v1_");
    token.insert_str(0, API_KEY_PREFIX);

    token_data.zeroize();

    let now = Utc::now();
    let api_key = ApiKey {
        id: api_key_id,
        created_at: now,
        updated_at: now,
        name,
        version,
        secret_hash: hash,
        expires_at,
        organization_id,
    };
    ApiKeyWithToken { api_key, token }
}

fn hash_api_key(
    api_key_id: Uuid,
    version: i16,
    organization_id: Uuid,
    secret: &[u8],
) -> [u8; API_KEY_HASH_SIZE] {
    let mut hasher = sha3::Sha3_512::new();

    hasher.write(api_key_id.as_bytes());
    hasher.write(&version.to_le_bytes());
    hasher.write(organization_id.as_bytes());
    hasher.write(secret);

    assert_eq!(hasher.output_size(), API_KEY_HASH_SIZE);
    hasher.finalize().into()
}
