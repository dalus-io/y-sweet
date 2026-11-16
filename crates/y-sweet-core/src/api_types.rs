use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct NewDocResponse {
    #[serde(rename = "docId")]
    pub doc_id: String,
}

#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, Debug)]
pub enum Authorization {
    #[serde(rename = "read-only")]
    ReadOnly,
    #[serde(rename = "full")]
    Full,
}

impl Authorization {
    fn full() -> Self {
        Self::Full
    }
}

#[derive(Deserialize)]
pub struct AuthDocRequest {
    #[serde(default = "Authorization::full")]
    pub authorization: Authorization,
    #[serde(rename = "userId")]
    pub user_id: Option<String>,
    /// An opaque label for the kind of writer the token is for (e.g. `"ui"`). The application
    /// owns the taxonomy; the server only carries it.
    #[serde(default)]
    pub writer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "validForSeconds")]
    pub valid_for_seconds: Option<u64>,
    /// Only read by a server that enforces user suspension. There, a token minted with a
    /// `userId` is bound to that user: it stops working when the user is suspended. `false`
    /// asks for a token that names the user (for attribution) without being bound to them,
    /// for a writer that acts for a user and is governed by other means. Absent means `true`.
    #[serde(default, rename = "userScoped")]
    pub user_scoped: Option<bool>,
}

impl Default for AuthDocRequest {
    fn default() -> Self {
        Self {
            authorization: Authorization::Full,
            user_id: None,
            writer: None,
            valid_for_seconds: None,
            user_scoped: None,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct ClientToken {
    /// The URL compatible with the y-websocket provider. The provider will append
    /// a document ID to this string and establish a WebSocket connection.
    pub url: String,

    /// The base URL for document-level endpoints.
    #[serde(rename = "baseUrl")]
    pub base_url: Option<String>,

    /// The document ID.
    #[serde(rename = "docId")]
    pub doc_id: String,

    /// An optional token that can be used to authenticate the client to the server.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,

    /// The authorization level of the client.
    #[serde(rename = "authorization")]
    pub authorization: Authorization,
}

#[derive(Deserialize, Debug)]
pub struct DocCreationRequest {
    /// The ID of the document to create. If not provided, a random ID will be generated.
    #[serde(skip_serializing_if = "Option::is_none", rename = "docId")]
    pub doc_id: Option<String>,
}

/// Validate that the document name contains only alphanumeric characters, dashes, and underscores.
/// This is the same alphabet used by nanoid when we generate a document name.
pub fn validate_doc_name(doc_name: &str) -> bool {
    if doc_name.is_empty() {
        return false;
    }
    for c in doc_name.chars() {
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return false;
        }
    }
    true
}
