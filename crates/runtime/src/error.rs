//! Unified error type.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, BridgeError>;

#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("cokret protocol error: {0}")]
    Cokret(String),

    #[error("app adapter error: {0}")]
    App(String),

    #[error("runtime error: {0}")]
    Runtime(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl From<cokret::Error> for BridgeError {
    fn from(e: cokret::Error) -> Self {
        BridgeError::Cokret(e.to_string())
    }
}

impl From<cokret::identifiers::IdentifierError> for BridgeError {
    fn from(e: cokret::identifiers::IdentifierError) -> Self {
        BridgeError::Cokret(e.to_string())
    }
}

#[cfg(feature = "db")]
impl From<diesel::result::Error> for BridgeError {
    fn from(e: diesel::result::Error) -> Self {
        BridgeError::Database(e.to_string())
    }
}

#[cfg(feature = "db")]
impl From<diesel::r2d2::PoolError> for BridgeError {
    fn from(e: diesel::r2d2::PoolError) -> Self {
        BridgeError::Database(e.to_string())
    }
}

pub fn redact_sensitive_url_values(input: impl AsRef<str>) -> String {
    let mut value = input.as_ref().to_owned();
    for key in ["access_token", "secret", "corpsecret", "appsecret", "guid"] {
        redact_query_value(&mut value, key);
    }
    redact_telegram_bot_token(&mut value);
    value
}

fn redact_query_value(value: &mut String, key: &str) {
    let needle = format!("{key}=");
    let mut search_from = 0;
    loop {
        let lower = value.to_ascii_lowercase();
        let Some(relative_start) = lower[search_from..].find(&needle) else {
            break;
        };
        let start = search_from + relative_start;
        let prefix_ok = start == 0 || matches!(value.as_bytes()[start - 1], b'?' | b'&');
        let value_start = start + needle.len();
        if !prefix_ok {
            search_from = value_start;
            continue;
        }
        let value_end = value[value_start..]
            .find(query_value_terminator)
            .map(|relative_end| value_start + relative_end)
            .unwrap_or_else(|| value.len());
        if value_end > value_start {
            value.replace_range(value_start..value_end, "<redacted>");
            search_from = value_start + "<redacted>".len();
        } else {
            search_from = value_start;
        }
    }
}

fn query_value_terminator(c: char) -> bool {
    matches!(
        c,
        '&' | ' ' | '\t' | '\r' | '\n' | '"' | '\'' | ')' | ']' | '}'
    )
}

fn redact_telegram_bot_token(value: &mut String) {
    let mut search_from = 0;
    while let Some(relative_start) = value[search_from..].find("/bot") {
        let value_start = search_from + relative_start + "/bot".len();
        let value_end = value[value_start..]
            .find(telegram_token_terminator)
            .map(|relative_end| value_start + relative_end)
            .unwrap_or_else(|| value.len());
        if value_end > value_start {
            value.replace_range(value_start..value_end, "<redacted>");
            search_from = value_start + "<redacted>".len();
        } else {
            search_from = value_start;
        }
    }
}

fn telegram_token_terminator(c: char) -> bool {
    matches!(
        c,
        '/' | ' ' | '\t' | '\r' | '\n' | '"' | '\'' | ')' | ']' | '}'
    )
}

#[cfg(test)]
mod tests {
    use super::redact_sensitive_url_values;

    #[test]
    fn redacts_sensitive_query_values() {
        let input =
            "request failed for https://api.example.test/path?corpsecret=abc&access_token=def&ok=1";
        let redacted = redact_sensitive_url_values(input);
        assert_eq!(
            redacted,
            "request failed for https://api.example.test/path?corpsecret=<redacted>&access_token=<redacted>&ok=1"
        );
    }

    #[test]
    fn redacts_telegram_bot_token_path_segment() {
        let input =
            "error for url (https://api.telegram.org/file/bot123456:ABCDEF/photos/file.jpg)";
        let redacted = redact_sensitive_url_values(input);
        assert_eq!(
            redacted,
            "error for url (https://api.telegram.org/file/bot<redacted>/photos/file.jpg)"
        );
    }
}
