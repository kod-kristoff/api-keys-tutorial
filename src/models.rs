use chrono::{DateTime, Utc};
use uuid::Uuid;

pub const API_KEY_SECRET_SIZE: usize = 32; // 256 bits
pub const API_KEY_HASH_SIZE: usize = 64; // 512 bits
pub const API_KEY_PREFIX: &str = "myservice";

#[derive(Clone, Debug, serde::Serialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    pub name: String,
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing)]
    pub version: i16,
    #[serde(skip_serializing)]
    pub secret_hash: [u8; API_KEY_HASH_SIZE],

    pub organization_id: Uuid,
}
