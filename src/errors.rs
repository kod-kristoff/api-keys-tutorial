use chrono::{DateTime, Utc};

#[derive(Debug)]
pub enum CreateApiKeyError {
    EmptyName,
    ExpiresAtBeforeNow(DateTime<Utc>),
}
