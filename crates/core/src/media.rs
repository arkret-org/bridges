//! Media bridging: app attachments ↔ cokret blobs. Wraps downloading a remote
//! URL, uploading to the cokret blob store, and downloading back. The actual
//! cokret blob calls live in [`crate::cokret_edge`].

use serde::{Deserialize, Serialize};

/// Information about a piece of media to be bridged.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MediaInfo {
    /// The remote downloadable URL (app-side attachment).
    pub url: Option<String>,
    /// The ready bytes (if already downloaded).
    #[serde(skip)]
    pub bytes: Option<Vec<u8>>,
    pub filename: String,
    pub mime_type: String,
    #[serde(default)]
    pub size: Option<u64>,
}

impl MediaInfo {
    pub fn from_url(
        url: impl Into<String>,
        filename: impl Into<String>,
        mime: impl Into<String>,
    ) -> Self {
        Self {
            url: Some(url.into()),
            bytes: None,
            filename: filename.into(),
            mime_type: mime.into(),
            size: None,
        }
    }

    /// Fetch the bytes pointed to by `url` (if not yet downloaded).
    pub async fn fetch(&mut self, http: &reqwest::Client) -> crate::Result<&[u8]> {
        if self.bytes.is_none() {
            let url = self
                .url
                .as_ref()
                .ok_or_else(|| crate::BridgeError::App("media is missing a url".into()))?;
            let resp = http
                .get(url)
                .send()
                .await
                .map_err(|e| crate::BridgeError::App(e.to_string()))?;
            let bytes = resp
                .bytes()
                .await
                .map_err(|e| crate::BridgeError::App(e.to_string()))?;
            self.size = Some(bytes.len() as u64);
            self.bytes = Some(bytes.to_vec());
        }
        Ok(self.bytes.as_deref().unwrap())
    }
}
