use crate::api_types::Authorization;
use bincode::Options;
use data_encoding::Encoding;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Display;
use subtle::ConstantTimeEq;
use thiserror::Error;

pub const DEFAULT_EXPIRATION_SECONDS: u64 = 60 * 60; // 60 minutes

/// This newtype is introduced to distinguish between a u64 meant to represent the current time
/// (currently passed as a raw u64), and a u64 meant to represent an expiration time.
/// We introduce this to intentonally break callers to `gen_doc_token` that do not explicitly
/// update to pass an expiration time, so that calls that use the old signature to pass a current
/// time do not compile.
/// Unit is milliseconds since Jan 1, 1970.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ExpirationTimeEpochMillis(pub u64);

impl ExpirationTimeEpochMillis {
    pub fn max() -> Self {
        Self(u64::MAX)
    }
}

/// This is a custom base64 encoder that is equivalent to BASE64URL_NOPAD for encoding,
/// but is tolerant when decoding of the “standard” alphabet and also of padding.
/// This is necessary for now because we used to use standard base64 encoding with padding,
/// but we can eventually remove it.
///
/// ```
/// use data_encoding::{Specification, BASE64URL_NOPAD, Translate};
/// let spec = Specification {
///     ignore: "=".to_string(),
///     translate: Translate {
///         from: "/+".to_string(),
///         to: "_-".to_string(),
///     },
///     ..BASE64URL_NOPAD.specification()
/// };
/// use y_sweet_core::auth::BASE64_CUSTOM;
/// assert_eq!(BASE64_CUSTOM, spec.encoding().unwrap());
/// ```
pub const BASE64_CUSTOM: Encoding = Encoding::internal_new(&[
    65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88,
    89, 90, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114,
    115, 116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, 65, 66,
    67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
    97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
    116, 117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, 65, 66, 67,
    68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97,
    98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116,
    117, 118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, 65, 66, 67, 68,
    69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 97, 98,
    99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117,
    118, 119, 120, 121, 122, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 45, 95, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 62, 128, 62, 128, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 128, 128, 128, 129, 128,
    128, 128, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
    24, 25, 128, 128, 128, 128, 63, 128, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
    40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128,
    128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 128, 30, 0,
]);

#[derive(Error, Debug, PartialEq, Eq)]
pub enum AuthError {
    #[error("The token is not a valid format")]
    InvalidToken,
    #[error("The token is expired")]
    Expired,
    #[error("The token is not valid for the requested resource")]
    InvalidResource,
    #[error("The token signature is invalid")]
    InvalidSignature,
    #[error("The key ID did not match")]
    KeyMismatch,
    #[error("The token is of a kind this server does not accept")]
    Unsupported,
}

#[derive(Serialize, Deserialize, PartialEq, PartialOrd, Debug)]
pub struct Authenticator {
    #[serde(with = "b64")]
    private_key: Vec<u8>,
    key_id: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct DocPermission {
    pub doc_id: String,
    pub authorization: Authorization,
}

/// The largest `user_id` the mint endpoint accepts, in bytes.
pub const MAX_ACTOR_USER_ID_BYTES: usize = 128;
/// The largest `writer` the mint endpoint accepts, in bytes.
pub const MAX_ACTOR_WRITER_BYTES: usize = 64;

/// The server-verified identity of whoever writes through a doc token.
///
/// Both fields are opaque to this server: the application that mints tokens owns their meaning.
/// The struct is part of the (positional, bincode) token payload, so fields must never be
/// added, removed, reordered or skipped during serialization.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Actor {
    pub user_id: Option<String>,
    pub writer: Option<String>,
}

/// `user_id` is never printed: actors end up in log lines through `{:?}` far too easily.
impl std::fmt::Debug for Actor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Actor")
            .field("user_id", &self.user_id.as_ref().map(|_| "<redacted>"))
            .field("writer", &self.writer)
            .finish()
    }
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum ActorError {
    #[error("user_id is longer than {MAX_ACTOR_USER_ID_BYTES} bytes")]
    UserIdTooLong,
    #[error("writer is longer than {MAX_ACTOR_WRITER_BYTES} bytes")]
    WriterTooLong,
}

impl Actor {
    /// Builds the actor for a mint request. Returns `Ok(None)` when the request names neither a
    /// user nor a writer, and an error when either is over its size limit.
    pub fn from_request(
        user_id: Option<String>,
        writer: Option<String>,
    ) -> Result<Option<Self>, ActorError> {
        if user_id
            .as_ref()
            .is_some_and(|v| v.len() > MAX_ACTOR_USER_ID_BYTES)
        {
            return Err(ActorError::UserIdTooLong);
        }
        if writer
            .as_ref()
            .is_some_and(|v| v.len() > MAX_ACTOR_WRITER_BYTES)
        {
            return Err(ActorError::WriterTooLong);
        }
        if user_id.is_none() && writer.is_none() {
            return Ok(None);
        }
        Ok(Some(Self { user_id, writer }))
    }
}

/// What a verified doc token grants, and on whose behalf.
#[derive(Debug, Clone, PartialEq)]
pub struct DocAccess {
    pub authorization: Authorization,
    /// `None` for server tokens and for doc tokens minted without an actor.
    pub actor: Option<Actor>,
}

impl DocAccess {
    /// Full, unattributed access: what a server token or a server without auth grants.
    pub fn full() -> Self {
        Self {
            authorization: Authorization::Full,
            actor: None,
        }
    }
}

// The payload is bincode and positional: variants may only ever be appended, and the fields of
// an existing variant may never change, or every outstanding token stops verifying. The
// indexes are shared with every build that mints tokens for the same key, including the Dalus
// production build of this fork (revision 4f1909b plus its user-suspension patch), which has
// used index 2 since before this variant list knew of it. The golden-bytes tests below pin
// each layout.
#[derive(Serialize, Deserialize)]
pub enum Permission {
    /// Index 0.
    Server,
    /// Index 1. Upstream's doc token.
    Doc(DocPermission),
    /// Index 2. A doc token bound to a user and that user's revocation generation (`None`
    /// for a token that is explicitly not user-scoped). Minted, and accepted, only by a server
    /// that enforces user suspension. The layout is the one the Dalus production build
    /// (revision 4f1909b plus its user-suspension patch) has always used, field for field.
    ///
    /// A server that does not enforce suspension rejects the token
    /// ([AuthError::Unsupported]): it cannot honour what the token binds, and accepting it as
    /// a plain doc token would turn a revocable token into one that survives its user's
    /// suspension.
    ManagedDoc(DocPermission, Option<(String, u64)>),
    /// Index 3. A doc token that carries the actor it writes for.
    AttributedDoc(DocPermission, Actor),
    /// Index 4. [Permission::ManagedDoc] that also carries the actor it writes for: what a
    /// server that enforces suspension mints when attributed tokens are on as well.
    ManagedAttributedDoc(DocPermission, Option<(String, u64)>, Actor),
}

/// What a verified managed doc token grants (see [Authenticator::verify_managed_doc_access]).
#[derive(Debug, Clone, PartialEq)]
pub struct ManagedDocAccess {
    pub access: DocAccess,
    /// The user the token is bound to and the revocation generation it was minted at. `None`
    /// for a server token and for a token minted without a user.
    pub user: Option<(String, u64)>,
    /// When the token expires, in milliseconds since the epoch. `None` for a server token.
    pub deadline: Option<u64>,
    /// Whether this was the server token rather than a doc token.
    pub server_token: bool,
}

/// A token's expiry as a deadline a connection can be held to: `None` when the token has no
/// expiry or the maximum one, which is how a token that never expires is minted.
pub fn finite_deadline(expiration_millis: Option<u64>) -> Option<u64> {
    expiration_millis.filter(|time| *time != u64::MAX)
}

/// The rule of a server that enforces token expiry: a doc token that can write must expire.
pub fn require_deadline_for_writes(
    authorization: Authorization,
    deadline: Option<u64>,
) -> Result<(), AuthError> {
    if matches!(authorization, Authorization::Full) && deadline.is_none() {
        return Err(AuthError::InvalidToken);
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
pub struct Payload {
    pub payload: Permission,
    pub expiration_millis: Option<ExpirationTimeEpochMillis>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthenticatedRequest {
    pub payload: Payload,
    pub token: Vec<u8>,
}

fn bincode_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, bincode::Error> {
    // This uses different defaults than the default bincode::serialize() function.
    bincode::DefaultOptions::new().serialize(&value)
}

fn bincode_decode<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> Result<T, bincode::Error> {
    // This uses different defaults than the default bincode::deserialize() function.
    bincode::DefaultOptions::new().deserialize(bytes)
}

fn b64_encode(bytes: &[u8]) -> String {
    BASE64_CUSTOM.encode(bytes)
}

fn b64_decode(input: &str) -> Result<Vec<u8>, AuthError> {
    BASE64_CUSTOM
        .decode(input.as_bytes())
        .map_err(|_| AuthError::InvalidToken)
}

mod b64 {
    use super::*;
    use serde::{de, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&b64_encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        b64_decode(&s).map_err(de::Error::custom)
    }
}

impl Payload {
    pub fn new(payload: Permission) -> Self {
        Self {
            payload,
            expiration_millis: None,
        }
    }

    pub fn new_with_expiration(
        payload: Permission,
        expiration_millis: ExpirationTimeEpochMillis,
    ) -> Self {
        Self {
            payload,
            expiration_millis: Some(expiration_millis),
        }
    }
}

fn hash(bytes: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let result = hasher.finalize();
    result.to_vec()
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct KeyId(String);

#[derive(Error, Debug, PartialEq, Eq)]
pub enum KeyIdError {
    #[error("The key ID cannot be an empty string")]
    EmptyString,
    #[error("The key ID contains an invalid character: {ch}")]
    InvalidCharacter { ch: char },
}

impl KeyId {
    pub fn new(key_id: String) -> Result<Self, KeyIdError> {
        if key_id.is_empty() {
            return Err(KeyIdError::EmptyString);
        }

        let valid_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        for ch in key_id.chars() {
            if !valid_chars.contains(ch) {
                return Err(KeyIdError::InvalidCharacter { ch });
            }
        }

        Ok(Self(key_id))
    }
}

impl Display for KeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<&str> for KeyId {
    type Error = KeyIdError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value.to_string())
    }
}

impl Authenticator {
    pub fn new(private_key: &str) -> Result<Self, AuthError> {
        let private_key = b64_decode(private_key)?;

        Ok(Self {
            private_key,
            key_id: None,
        })
    }

    pub fn server_token(&self) -> String {
        self.sign(Payload::new(Permission::Server))
    }

    fn sign(&self, payload: Payload) -> String {
        let mut hash_payload =
            bincode_encode(&payload).expect("Bincode serialization should not fail.");
        hash_payload.extend_from_slice(&self.private_key);

        let token = hash(&hash_payload);

        let auth_req = AuthenticatedRequest { payload, token };

        let auth_enc = bincode_encode(&auth_req).expect("Bincode serialization should not fail.");
        let result = b64_encode(&auth_enc);
        if let Some(key_id) = &self.key_id {
            format!("{}.{}", key_id, result)
        } else {
            result
        }
    }

    fn verify(&self, token: &str, current_time: u64) -> Result<Payload, AuthError> {
        let token = if let Some((prefix, token)) = token.split_once('.') {
            if Some(prefix) != self.key_id.as_deref() {
                return Err(AuthError::KeyMismatch);
            }

            token
        } else {
            if self.key_id.is_some() {
                return Err(AuthError::KeyMismatch);
            }

            token
        };

        let auth_req: AuthenticatedRequest =
            bincode_decode(&b64_decode(token)?).or(Err(AuthError::InvalidToken))?;

        let mut payload =
            bincode_encode(&auth_req.payload).expect("Bincode serialization should not fail.");
        payload.extend_from_slice(&self.private_key);

        let expected_token = hash(&payload);

        // Constant time, so the comparison does not reveal how much of a forged signature is
        // right. (`ct_eq` on slices of different lengths is false without comparing contents.)
        if !bool::from(expected_token.as_slice().ct_eq(auth_req.token.as_slice())) {
            Err(AuthError::InvalidSignature)
        } else if auth_req
            .payload
            .expiration_millis
            .unwrap_or(ExpirationTimeEpochMillis::max())
            .0
            < current_time
        {
            Err(AuthError::Expired)
        } else {
            Ok(auth_req.payload)
        }
    }

    pub fn with_key_id(self, key_id: KeyId) -> Self {
        Self {
            key_id: Some(key_id.0),
            ..self
        }
    }

    pub fn verify_server_token(
        &self,
        token: &str,
        current_time_epoch_millis: u64,
    ) -> Result<(), AuthError> {
        let payload = self.verify(token, current_time_epoch_millis)?;
        match payload {
            Payload {
                payload: Permission::Server,
                ..
            } => Ok(()),
            _ => Err(AuthError::InvalidResource),
        }
    }

    pub fn private_key(&self) -> String {
        b64_encode(&self.private_key)
    }

    pub fn gen_doc_token(
        &self,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
    ) -> String {
        let payload = Payload::new_with_expiration(
            Permission::Doc(DocPermission {
                doc_id: doc_id.to_string(),
                authorization,
            }),
            expiration_time,
        );
        self.sign(payload)
    }

    /// Like [Authenticator::gen_doc_token], but binds `actor` into the token when one is given.
    /// Without an actor this mints exactly the token `gen_doc_token` does.
    ///
    /// Binaries that predate `Permission::AttributedDoc` reject a token carrying an actor, so
    /// callers must only pass one once every verifier of the token has been upgraded.
    pub fn gen_doc_token_with_actor(
        &self,
        doc_id: &str,
        authorization: Authorization,
        expiration_time: ExpirationTimeEpochMillis,
        actor: Option<Actor>,
    ) -> String {
        let doc_permission = DocPermission {
            doc_id: doc_id.to_string(),
            authorization,
        };
        let permission = match actor {
            Some(actor) => Permission::AttributedDoc(doc_permission, actor),
            None => Permission::Doc(doc_permission),
        };
        self.sign(Payload::new_with_expiration(permission, expiration_time))
    }

    fn verify_token(
        &self,
        token: &str,
        current_time_epoch_millis: u64,
    ) -> Result<Permission, AuthError> {
        let payload = self.verify(token, current_time_epoch_millis)?;
        Ok(payload.payload)
    }

    pub fn verify_doc_token(
        &self,
        token: &str,
        doc: &str,
        current_time_epoch_millis: u64,
    ) -> Result<DocAccess, AuthError> {
        let payload = self.verify_token(token, current_time_epoch_millis)?;

        let (doc_permission, actor) = match payload {
            Permission::Doc(doc_permission) => (doc_permission, None),
            Permission::AttributedDoc(doc_permission, actor) => (doc_permission, Some(actor)),
            // Server tokens can access any doc, and are never attributed.
            Permission::Server => return Ok(DocAccess::full()),
            // See the variants: only a server that enforces suspension may accept them.
            Permission::ManagedDoc(..) | Permission::ManagedAttributedDoc(..) => {
                return Err(AuthError::Unsupported)
            }
        };

        if doc_permission.doc_id == doc {
            Ok(DocAccess {
                authorization: doc_permission.authorization,
                actor,
            })
        } else {
            Err(AuthError::InvalidResource)
        }
    }

    /// Managed tokens bind optional user identity and revocation generation in the signature.
    pub fn gen_managed_doc_token(
        &self,
        doc: &str,
        authorization: Authorization,
        user: Option<(String, u64)>,
        expiry: ExpirationTimeEpochMillis,
    ) -> String {
        self.gen_managed_doc_token_with_actor(doc, authorization, user, expiry, None)
    }

    /// Like [Authenticator::gen_managed_doc_token], but also binds `actor` when one is given.
    /// Without an actor this mints exactly the token `gen_managed_doc_token` does.
    pub fn gen_managed_doc_token_with_actor(
        &self,
        doc: &str,
        authorization: Authorization,
        user: Option<(String, u64)>,
        expiry: ExpirationTimeEpochMillis,
        actor: Option<Actor>,
    ) -> String {
        let permission = DocPermission {
            doc_id: doc.to_owned(),
            authorization,
        };
        let permission = match actor {
            Some(actor) => Permission::ManagedAttributedDoc(permission, user, actor),
            None => Permission::ManagedDoc(permission, user),
        };
        self.sign(Payload::new_with_expiration(permission, expiry))
    }

    /// Verifies a token for a server that enforces user suspension. Only server tokens and
    /// managed doc tokens pass: a token that carries no revocation generation cannot be
    /// revoked, so every other kind is refused and its holder has to authenticate again.
    ///
    /// The caller still has to check the returned user against its revocation state.
    pub fn verify_managed_doc_access(
        &self,
        token: &str,
        doc: &str,
        now: u64,
    ) -> Result<ManagedDocAccess, AuthError> {
        let payload = self.verify(token, now)?;
        let deadline = payload.expiration_millis.map(|e| e.0);
        let (permission, user, actor) = match payload.payload {
            Permission::Server => {
                return Ok(ManagedDocAccess {
                    access: DocAccess::full(),
                    user: None,
                    deadline: None,
                    server_token: true,
                })
            }
            Permission::ManagedDoc(permission, user) => (permission, user, None),
            Permission::ManagedAttributedDoc(permission, user, actor) => {
                (permission, user, Some(actor))
            }
            // Legacy client tokens have no identity. Force re-authentication after deployment.
            Permission::Doc(_) | Permission::AttributedDoc(..) => {
                return Err(AuthError::InvalidResource)
            }
        };
        if permission.doc_id != doc {
            return Err(AuthError::InvalidResource);
        }
        Ok(ManagedDocAccess {
            access: DocAccess {
                authorization: permission.authorization,
                actor,
            },
            user,
            deadline,
            server_token: false,
        })
    }

    /// [Authenticator::verify_managed_doc_access] without the actor: the authorization, the
    /// user and generation the token is bound to, and its deadline.
    // The signature the user-suspension patch gave it.
    #[allow(clippy::type_complexity)]
    pub fn verify_managed_doc_token(
        &self,
        token: &str,
        doc: &str,
        now: u64,
    ) -> Result<(Authorization, Option<(String, u64)>, Option<u64>), AuthError> {
        let managed = self.verify_managed_doc_access(token, doc, now)?;
        Ok((managed.access.authorization, managed.user, managed.deadline))
    }

    /// Appliance WebSockets retain the authenticated deadline for the connection's
    /// lifetime. Root server tokens remain unbounded for trusted internal clients.
    pub fn verify_expiring_doc_token(
        &self,
        token: &str,
        doc: &str,
        current_time_epoch_millis: u64,
    ) -> Result<(Authorization, Option<u64>), AuthError> {
        self.verify_expiring_doc_access(token, doc, current_time_epoch_millis)
            .map(|(access, deadline)| (access.authorization, deadline))
    }

    /// [Authenticator::verify_expiring_doc_token] with the actor of an attributed token. A
    /// token with full access must carry a deadline (an expiry that is neither absent nor
    /// the maximum); the deadline of any doc token is returned for the connection to keep.
    pub fn verify_expiring_doc_access(
        &self,
        token: &str,
        doc: &str,
        current_time_epoch_millis: u64,
    ) -> Result<(DocAccess, Option<u64>), AuthError> {
        let payload = self.verify(token, current_time_epoch_millis)?;
        let deadline = finite_deadline(payload.expiration_millis.map(|time| time.0));
        let (permission, actor) = match payload.payload {
            Permission::Server => return Ok((DocAccess::full(), None)),
            Permission::Doc(permission) => (permission, None),
            Permission::AttributedDoc(permission, actor) => (permission, Some(actor)),
            Permission::ManagedDoc(..) | Permission::ManagedAttributedDoc(..) => {
                return Err(AuthError::InvalidResource)
            }
        };
        if permission.doc_id != doc {
            return Err(AuthError::InvalidResource);
        }
        require_deadline_for_writes(permission.authorization, deadline)?;
        Ok((
            DocAccess {
                authorization: permission.authorization,
                actor,
            },
            deadline,
        ))
    }

    pub fn gen_key() -> Result<Authenticator, AuthError> {
        let key = rand::thread_rng().gen::<[u8; 30]>();
        let key = b64_encode(&key);

        let authenticator = Authenticator::new(&key)?;
        Ok(authenticator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flex_b64() {
        let expect = [3, 242, 3, 248, 6, 220, 118];

        assert_eq!(b64_decode("A/ID+Abcdg==").unwrap(), expect);
        assert_eq!(b64_decode("A/ID+Abcdg").unwrap(), expect);

        assert_eq!(b64_decode("A_ID-Abcdg==").unwrap(), expect);
        assert_eq!(b64_decode("A_ID-Abcdg").unwrap(), expect);
    }

    #[test]
    fn test_b64_encode_options() {
        let data = [3, 242, 3, 248, 6, 220, 118];

        assert_eq!(b64_encode(&data), "A_ID-Abcdg");
    }

    #[test]
    fn test_simple_auth() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
        );
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(DocAccess {
                authorization: Authorization::Full,
                actor: None
            })
        ));
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", DEFAULT_EXPIRATION_SECONDS + 1),
            Err(AuthError::Expired)
        ));
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc456", 0),
            Err(AuthError::InvalidResource)
        ));
    }

    #[test]
    fn appliance_deadlines_preserve_root_and_read_only_access() {
        let auth = Authenticator::gen_key().unwrap();
        let bounded =
            auth.gen_doc_token("doc", Authorization::Full, ExpirationTimeEpochMillis(1000));
        assert!(matches!(
            auth.verify_expiring_doc_token(&bounded, "doc", 100),
            Ok((Authorization::Full, Some(1000)))
        ));
        assert!(auth
            .verify_expiring_doc_token(&bounded, "other", 100)
            .is_err());
        assert!(auth
            .verify_expiring_doc_token(&bounded, "doc", 1001)
            .is_err());
        let unbounded = auth.sign(Payload::new(Permission::Doc(DocPermission {
            doc_id: "doc".into(),
            authorization: Authorization::Full,
        })));
        assert!(auth
            .verify_expiring_doc_token(&unbounded, "doc", 100)
            .is_err());
        assert!(matches!(
            auth.verify_doc_token(&unbounded, "doc", 100),
            Ok(DocAccess {
                authorization: Authorization::Full,
                actor: None
            })
        ));
        let maximum =
            auth.gen_doc_token("doc", Authorization::Full, ExpirationTimeEpochMillis::max());
        assert!(auth
            .verify_expiring_doc_token(&maximum, "doc", 100)
            .is_err());
        let read_only = auth.sign(Payload::new(Permission::Doc(DocPermission {
            doc_id: "doc".into(),
            authorization: Authorization::ReadOnly,
        })));
        assert!(matches!(
            auth.verify_expiring_doc_token(&read_only, "doc", 100),
            Ok((Authorization::ReadOnly, None))
        ));
        assert!(matches!(
            auth.verify_expiring_doc_token(&auth.server_token(), "doc", 100),
            Ok((Authorization::Full, None))
        ));
    }

    #[test]
    fn appliance_deadlines_apply_to_attributed_tokens_too() {
        let auth = Authenticator::gen_key().unwrap();
        let alice = actor(Some("alice"), Some("ui"));
        let mint = |authorization, expiry| {
            auth.gen_doc_token_with_actor("doc", authorization, expiry, Some(alice.clone()))
        };
        let bounded = mint(Authorization::Full, ExpirationTimeEpochMillis(1000));
        assert_eq!(
            auth.verify_expiring_doc_access(&bounded, "doc", 100),
            Ok((
                DocAccess {
                    authorization: Authorization::Full,
                    actor: Some(alice.clone()),
                },
                Some(1000)
            ))
        );
        assert_eq!(
            auth.verify_expiring_doc_access(&bounded, "doc", 1001),
            Err(AuthError::Expired)
        );
        assert_eq!(
            auth.verify_expiring_doc_access(&bounded, "other", 100),
            Err(AuthError::InvalidResource)
        );
        // Full access without a deadline is refused, attributed or not.
        let maximum = mint(Authorization::Full, ExpirationTimeEpochMillis::max());
        assert_eq!(
            auth.verify_expiring_doc_access(&maximum, "doc", 100),
            Err(AuthError::InvalidToken)
        );
        let read_only = mint(Authorization::ReadOnly, ExpirationTimeEpochMillis::max());
        assert!(matches!(
            auth.verify_expiring_doc_access(&read_only, "doc", 100),
            Ok((_, None))
        ));
        // Managed tokens belong to a server that enforces suspension.
        let managed = auth.gen_managed_doc_token(
            "doc",
            Authorization::Full,
            None,
            ExpirationTimeEpochMillis(1000),
        );
        assert_eq!(
            auth.verify_expiring_doc_access(&managed, "doc", 100),
            Err(AuthError::InvalidResource)
        );
    }

    #[test]
    fn managed_tokens_verify_only_as_managed_tokens() {
        let auth = Authenticator::gen_key().unwrap();
        let expiry = ExpirationTimeEpochMillis(1000);
        let user = Some(("member".to_string(), 3));
        let alice = actor(Some("member"), Some("ui"));

        let plain = auth.gen_managed_doc_token("doc", Authorization::Full, user.clone(), expiry);
        assert_eq!(
            auth.verify_managed_doc_token(&plain, "doc", 100),
            Ok((Authorization::Full, user.clone(), Some(1000)))
        );
        assert_eq!(
            auth.verify_managed_doc_access(&plain, "doc", 100)
                .unwrap()
                .access
                .actor,
            None
        );
        let attributed = auth.gen_managed_doc_token_with_actor(
            "doc",
            Authorization::ReadOnly,
            user.clone(),
            expiry,
            Some(alice.clone()),
        );
        assert_eq!(
            auth.verify_managed_doc_access(&attributed, "doc", 100),
            Ok(ManagedDocAccess {
                access: DocAccess {
                    authorization: Authorization::ReadOnly,
                    actor: Some(alice.clone()),
                },
                user: user.clone(),
                deadline: Some(1000),
                server_token: false,
            })
        );
        let unscoped = auth.gen_managed_doc_token("doc", Authorization::Full, None, expiry);
        assert_eq!(
            auth.verify_managed_doc_token(&unscoped, "doc", 100),
            Ok((Authorization::Full, None, Some(1000)))
        );
        assert_eq!(
            auth.verify_managed_doc_token(&auth.server_token(), "doc", 100),
            Ok((Authorization::Full, None, None))
        );

        for managed in [&plain, &attributed, &unscoped] {
            assert_eq!(
                auth.verify_managed_doc_access(managed, "other", 100),
                Err(AuthError::InvalidResource)
            );
            assert_eq!(
                auth.verify_managed_doc_access(managed, "doc", 1001),
                Err(AuthError::Expired)
            );
            // A server that does not enforce suspension refuses them.
            assert_eq!(
                auth.verify_doc_token(managed, "doc", 100),
                Err(AuthError::Unsupported)
            );
            assert_eq!(
                auth.verify_server_token(managed, 100),
                Err(AuthError::InvalidResource)
            );
        }

        // A server that enforces suspension refuses tokens that carry no generation.
        let legacy = auth.gen_doc_token("doc", Authorization::Full, expiry);
        let legacy_attributed =
            auth.gen_doc_token_with_actor("doc", Authorization::Full, expiry, Some(alice));
        for token in [&legacy, &legacy_attributed] {
            assert_eq!(
                auth.verify_managed_doc_access(token, "doc", 100),
                Err(AuthError::InvalidResource)
            );
        }
    }

    #[test]
    fn test_read_only_auth() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::ReadOnly,
            ExpirationTimeEpochMillis(0),
        );
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(DocAccess {
                authorization: Authorization::ReadOnly,
                actor: None
            })
        ));
    }

    #[test]
    fn test_server_token_for_doc_auth() {
        let authenticator = Authenticator::gen_key().unwrap();
        let server_token = authenticator.server_token();
        assert!(matches!(
            authenticator.verify_doc_token(&server_token, "doc123", 0),
            Ok(DocAccess {
                authorization: Authorization::Full,
                actor: None
            })
        ));
    }

    #[test]
    fn test_key_id() {
        let authenticator = Authenticator::gen_key()
            .unwrap()
            .with_key_id("myKeyId".try_into().unwrap());
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
        );
        assert!(
            token.starts_with("myKeyId."),
            "Token {} does not start with myKeyId.",
            token
        );
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(DocAccess {
                authorization: Authorization::Full,
                actor: None
            })
        ));

        let token = authenticator.server_token();
        assert!(
            token.starts_with("myKeyId."),
            "Token {} does not start with myKeyId.",
            token
        );
        assert_eq!(authenticator.verify_server_token(&token, 0), Ok(()));
    }

    #[test]
    fn test_construct_key_id() {
        assert_eq!(KeyId::new("".to_string()), Err(KeyIdError::EmptyString));
        assert_eq!(
            KeyId::new("*".to_string()),
            Err(KeyIdError::InvalidCharacter { ch: '*' })
        );
        assert_eq!(
            KeyId::new("myKeyId".to_string()),
            Ok(KeyId("myKeyId".to_string()))
        );
    }

    #[test]
    fn test_key_id_mismatch() {
        let authenticator = Authenticator::gen_key()
            .unwrap()
            .with_key_id("myKeyId".try_into().unwrap());
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
        );
        let token = token.replace("myKeyId.", "aDifferentKeyId.");
        assert!(token.starts_with("aDifferentKeyId."));
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Err(AuthError::KeyMismatch)
        ));
    }

    #[test]
    fn test_missing_key_id() {
        let authenticator = Authenticator::gen_key()
            .unwrap()
            .with_key_id("myKeyId".try_into().unwrap());
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
        );
        let token = token.replace("myKeyId.", "");
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Err(AuthError::KeyMismatch)
        ));
    }

    #[test]
    fn test_unexpected_key_id() {
        let authenticator = Authenticator::gen_key().unwrap();
        let token = authenticator.gen_doc_token(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
        );
        let token = format!("unexpectedKeyId.{}", token);
        assert!(matches!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Err(AuthError::KeyMismatch)
        ));
    }

    #[test]
    fn test_invalid_signature() {
        let authenticator = Authenticator::gen_key().unwrap();
        let actual_payload = Payload::new(Permission::Doc(DocPermission {
            doc_id: "doc123".to_string(),
            authorization: Authorization::Full,
        }));
        let mut encoded_payload =
            bincode_encode(&actual_payload).expect("Bincode serialization should not fail.");
        encoded_payload.extend_from_slice(&authenticator.private_key);

        let token = hash(&encoded_payload);

        let auth_req = AuthenticatedRequest {
            payload: Payload::new(Permission::Doc(DocPermission {
                doc_id: "abc123".to_string(),
                authorization: Authorization::Full,
            })),
            token,
        };

        let auth_enc = bincode_encode(&auth_req).expect("Bincode serialization should not fail.");
        let signed = b64_encode(&auth_enc);

        assert!(matches!(
            authenticator.verify_doc_token(&signed, "doc123", 0),
            Err(AuthError::InvalidSignature)
        ));
        assert!(matches!(
            authenticator.verify_doc_token(&signed, "abc123", 0),
            Err(AuthError::InvalidSignature)
        ));
    }

    #[test]
    fn test_roundtrip_serde_authenticator() {
        let authenticator = Authenticator::gen_key().unwrap();
        let serialized = serde_json::to_string(&authenticator).unwrap();
        let deserialized: Authenticator = serde_json::from_str(&serialized).unwrap();
        assert_eq!(authenticator, deserialized);
    }

    fn actor(user_id: Option<&str>, writer: Option<&str>) -> Actor {
        Actor {
            user_id: user_id.map(str::to_string),
            writer: writer.map(str::to_string),
        }
    }

    #[test]
    fn test_attributed_doc_token_roundtrip() {
        let authenticator = Authenticator::gen_key().unwrap();
        let expected = actor(Some("user-1"), Some("ui"));
        let token = authenticator.gen_doc_token_with_actor(
            "doc123",
            Authorization::Full,
            ExpirationTimeEpochMillis(0),
            Some(expected.clone()),
        );

        assert_eq!(
            authenticator.verify_doc_token(&token, "doc123", 0),
            Ok(DocAccess {
                authorization: Authorization::Full,
                actor: Some(expected),
            })
        );
        assert_eq!(
            authenticator.verify_doc_token(&token, "doc456", 0),
            Err(AuthError::InvalidResource)
        );
        assert_eq!(
            authenticator.verify_doc_token(&token, "doc123", 1),
            Err(AuthError::Expired)
        );
        // An attributed doc token is still not a server token.
        assert_eq!(
            authenticator.verify_server_token(&token, 0),
            Err(AuthError::InvalidResource)
        );
    }

    #[test]
    fn test_attributed_doc_token_partial_actor_and_read_only() {
        let authenticator = Authenticator::gen_key()
            .unwrap()
            .with_key_id("myKeyId".try_into().unwrap());
        for expected in [actor(None, Some("agent")), actor(Some("user-1"), None)] {
            let token = authenticator.gen_doc_token_with_actor(
                "doc123",
                Authorization::ReadOnly,
                ExpirationTimeEpochMillis(0),
                Some(expected.clone()),
            );
            assert_eq!(
                authenticator.verify_doc_token(&token, "doc123", 0),
                Ok(DocAccess {
                    authorization: Authorization::ReadOnly,
                    actor: Some(expected),
                })
            );
        }
    }

    #[test]
    fn test_doc_token_without_actor_is_the_plain_doc_token() {
        let authenticator = Authenticator::gen_key().unwrap();
        let expiration = ExpirationTimeEpochMillis(1234);
        assert_eq!(
            authenticator.gen_doc_token_with_actor("doc123", Authorization::Full, expiration, None),
            authenticator.gen_doc_token("doc123", Authorization::Full, expiration),
        );
    }

    /// A token in the format every binary before `Permission::AttributedDoc` minted. The bytes
    /// were produced independently of this crate (bincode varint layout written out by hand:
    /// variant 1, doc id, authorization, expiration, then the SHA-256 of payload + key), so this
    /// fails if the payload layout of existing tokens ever shifts.
    #[test]
    fn test_old_format_token_verifies_without_actor() {
        let authenticator = Authenticator::new("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd").unwrap();
        let old_token = "AQZkb2MxMjMBAf3__________yBWZatYGvHMXUiFyJcgDOrKestcqJ8SOUawshErWx-Olg";

        assert_eq!(
            authenticator.verify_doc_token(old_token, "doc123", 0),
            Ok(DocAccess {
                authorization: Authorization::Full,
                actor: None,
            })
        );
        // And the current code still mints that exact token for the same input.
        assert_eq!(
            authenticator.gen_doc_token(
                "doc123",
                Authorization::Full,
                ExpirationTimeEpochMillis::max()
            ),
            old_token
        );
    }

    // --- Wire format ---------------------------------------------------------------------
    //
    // The expected bytes below are written out by hand from the bincode layout (variant index,
    // then each field in order; strings and byte vectors are a length and the bytes; an
    // `Option` is 0, or 1 and the value; integers are varints, a value over 250 taking the
    // marker 0xFB and two little-endian bytes). They do not come from this crate's encoder, so
    // they fail if a variant moves or a field changes.

    /// "doc", full access, as every variant with a `DocPermission` starts.
    const DOC_FULL: [u8; 5] = [3, b'd', b'o', b'c', 1];
    /// `Some(ExpirationTimeEpochMillis(1000))`.
    const EXPIRES_AT_1000: [u8; 4] = [1, 0xFB, 0xE8, 0x03];
    const GOLDEN_KEY: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";

    fn bytes(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    /// The token a server holding `GOLDEN_KEY` issues for these payload bytes: the payload,
    /// then the 32-byte SHA-256 of payload and key, as base64.
    fn token_for(payload: &[u8]) -> String {
        let key = b64_decode(GOLDEN_KEY).unwrap();
        let signature = hash(&bytes(&[payload, &key]));
        b64_encode(&bytes(&[payload, &[32], &signature]))
    }

    fn golden_payloads() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("server", vec![0, 0]),
            ("doc", bytes(&[&[1], &DOC_FULL, &EXPIRES_AT_1000])),
            (
                "managed, user-1 at generation 7",
                bytes(&[&[2], &DOC_FULL, &[1, 6], b"user-1", &[7], &EXPIRES_AT_1000]),
            ),
            (
                "managed, user-1 at generation 0",
                bytes(&[&[2], &DOC_FULL, &[1, 6], b"user-1", &[0], &EXPIRES_AT_1000]),
            ),
            (
                "managed, no user",
                bytes(&[&[2], &DOC_FULL, &[0], &EXPIRES_AT_1000]),
            ),
            (
                "attributed, user-1 as ui",
                bytes(&[
                    &[3],
                    &DOC_FULL,
                    &[1, 6],
                    b"user-1",
                    &[1, 2],
                    b"ui",
                    &EXPIRES_AT_1000,
                ]),
            ),
            (
                "attributed, user-1 and no writer",
                bytes(&[&[3], &DOC_FULL, &[1, 6], b"user-1", &[0], &EXPIRES_AT_1000]),
            ),
            (
                "managed and attributed, user-1 at generation 7 as ui",
                bytes(&[
                    &[4],
                    &DOC_FULL,
                    &[1, 6],
                    b"user-1",
                    &[7],
                    &[1, 6],
                    b"user-1",
                    &[1, 2],
                    b"ui",
                    &EXPIRES_AT_1000,
                ]),
            ),
            (
                "managed and attributed, no user, writer only",
                bytes(&[
                    &[4],
                    &DOC_FULL,
                    &[0],
                    &[0],
                    &[1, 2],
                    b"ui",
                    &EXPIRES_AT_1000,
                ]),
            ),
        ]
    }

    #[test]
    fn every_permission_variant_has_its_pinned_bytes() {
        let doc = || DocPermission {
            doc_id: "doc".to_string(),
            authorization: Authorization::Full,
        };
        let expiring =
            |permission| Payload::new_with_expiration(permission, ExpirationTimeEpochMillis(1000));
        let user = |generation| Some(("user-1".to_string(), generation));
        let built = [
            Payload::new(Permission::Server),
            expiring(Permission::Doc(doc())),
            expiring(Permission::ManagedDoc(doc(), user(7))),
            expiring(Permission::ManagedDoc(doc(), user(0))),
            expiring(Permission::ManagedDoc(doc(), None)),
            expiring(Permission::AttributedDoc(
                doc(),
                actor(Some("user-1"), Some("ui")),
            )),
            expiring(Permission::AttributedDoc(
                doc(),
                actor(Some("user-1"), None),
            )),
            expiring(Permission::ManagedAttributedDoc(
                doc(),
                user(7),
                actor(Some("user-1"), Some("ui")),
            )),
            expiring(Permission::ManagedAttributedDoc(
                doc(),
                None,
                actor(None, Some("ui")),
            )),
        ];
        let golden = golden_payloads();
        assert_eq!(built.len(), golden.len());
        for (payload, (name, expected)) in built.iter().zip(&golden) {
            assert_eq!(&bincode_encode(payload).unwrap(), expected, "{name}");
            // And the bytes decode to a payload that encodes to the same bytes.
            let decoded: Payload = bincode_decode(expected).unwrap();
            assert_eq!(&bincode_encode(&decoded).unwrap(), expected, "{name}");
        }
    }

    #[test]
    fn tokens_of_every_variant_are_read_as_what_they_are() {
        let authenticator = Authenticator::new(GOLDEN_KEY).unwrap();
        let verify = |name: &str| {
            let (_, payload) = golden_payloads()
                .into_iter()
                .find(|(golden, _)| *golden == name)
                .unwrap();
            authenticator.verify_doc_token(&token_for(&payload), "doc", 1000)
        };
        let full = |actor| {
            Ok(DocAccess {
                authorization: Authorization::Full,
                actor,
            })
        };

        assert_eq!(verify("server"), full(None));
        assert_eq!(verify("doc"), full(None));
        assert_eq!(
            verify("attributed, user-1 as ui"),
            full(Some(actor(Some("user-1"), Some("ui"))))
        );
        assert_eq!(
            verify("attributed, user-1 and no writer"),
            full(Some(actor(Some("user-1"), None)))
        );

        // Tokens of the production build that enforces user suspension (4f1909b plus its
        // patch). Without suspension enforcement they are refused, never read as some other
        // permission. Generation 0 is the case that was: with the attributed variant at index
        // 2, these bytes were a valid attributed token for user-1 with full access.
        let verify_managed = |name: &str| {
            let (_, payload) = golden_payloads()
                .into_iter()
                .find(|(golden, _)| *golden == name)
                .unwrap();
            authenticator.verify_managed_doc_access(&token_for(&payload), "doc", 1000)
        };
        let managed = |user: Option<(&str, u64)>, actor| {
            Ok(ManagedDocAccess {
                access: DocAccess {
                    authorization: Authorization::Full,
                    actor,
                },
                user: user.map(|(user, generation)| (user.to_string(), generation)),
                deadline: Some(1000),
                server_token: false,
            })
        };
        for (name, user) in [
            ("managed, user-1 at generation 7", Some(("user-1", 7))),
            ("managed, user-1 at generation 0", Some(("user-1", 0))),
            ("managed, no user", None),
        ] {
            assert_eq!(verify(name), Err(AuthError::Unsupported), "{name}");
            // With enforcement they are read exactly as that build wrote them.
            assert_eq!(verify_managed(name), managed(user, None), "{name}");
        }
        assert_eq!(
            verify_managed("managed and attributed, user-1 at generation 7 as ui"),
            managed(Some(("user-1", 7)), Some(actor(Some("user-1"), Some("ui"))))
        );
        assert_eq!(
            verify_managed("managed and attributed, no user, writer only"),
            managed(None, Some(actor(None, Some("ui"))))
        );
        assert_eq!(
            verify("managed and attributed, user-1 at generation 7 as ui"),
            Err(AuthError::Unsupported)
        );
        assert_eq!(
            verify_managed("attributed, user-1 as ui"),
            Err(AuthError::InvalidResource)
        );
        assert_eq!(verify_managed("doc"), Err(AuthError::InvalidResource));

        // Why the index matters: these two payloads differ in nothing but it.
        let golden = golden_payloads();
        assert_eq!(golden[3].1[1..], golden[6].1[1..]);

        // The signature is over the payload bytes: a token is not accepted under another
        // variant's index.
        let (_, attributed) = golden_payloads().remove(6);
        let mut forged = token_for(&attributed).into_bytes();
        assert_eq!(forged[0], b'A'); // "Aw..." is index 3; "Ag..." would be index 2.
        forged[1] = b'g';
        assert_eq!(
            authenticator.verify_doc_token(&String::from_utf8(forged).unwrap(), "doc", 1000),
            Err(AuthError::InvalidSignature)
        );
    }

    #[test]
    fn each_mint_function_produces_its_pinned_token() {
        let authenticator = Authenticator::new(GOLDEN_KEY).unwrap();
        let expiry = ExpirationTimeEpochMillis(1000);
        let golden = golden_payloads();
        assert_eq!(
            authenticator.gen_doc_token("doc", Authorization::Full, expiry),
            token_for(&golden[1].1)
        );
        assert_eq!(
            authenticator.gen_doc_token_with_actor(
                "doc",
                Authorization::Full,
                expiry,
                Some(actor(Some("user-1"), Some("ui")))
            ),
            token_for(&golden[5].1)
        );
        assert_eq!(authenticator.server_token(), token_for(&golden[0].1));
        // What a server that enforces suspension mints: the production build's token, bit
        // for bit, and the combined one only when there is an actor to carry.
        let user = Some(("user-1".to_string(), 7));
        assert_eq!(
            authenticator.gen_managed_doc_token("doc", Authorization::Full, user.clone(), expiry),
            token_for(&golden[2].1)
        );
        assert_eq!(
            authenticator.gen_managed_doc_token("doc", Authorization::Full, None, expiry),
            token_for(&golden[4].1)
        );
        assert_eq!(
            authenticator.gen_managed_doc_token_with_actor(
                "doc",
                Authorization::Full,
                user,
                expiry,
                Some(actor(Some("user-1"), Some("ui")))
            ),
            token_for(&golden[7].1)
        );
    }

    #[test]
    fn test_actor_from_request_limits() {
        assert_eq!(Actor::from_request(None, None), Ok(None));
        assert_eq!(
            Actor::from_request(Some("user-1".to_string()), None),
            Ok(Some(actor(Some("user-1"), None)))
        );

        let max_user_id = "u".repeat(MAX_ACTOR_USER_ID_BYTES);
        let max_writer = "w".repeat(MAX_ACTOR_WRITER_BYTES);
        assert_eq!(
            Actor::from_request(Some(max_user_id.clone()), Some(max_writer.clone())),
            Ok(Some(actor(Some(&max_user_id), Some(&max_writer))))
        );

        assert_eq!(
            Actor::from_request(Some(format!("{max_user_id}u")), None),
            Err(ActorError::UserIdTooLong)
        );
        assert_eq!(
            Actor::from_request(None, Some(format!("{max_writer}w"))),
            Err(ActorError::WriterTooLong)
        );
        // The limit is in bytes, not characters.
        assert_eq!(
            Actor::from_request(None, Some("é".repeat(MAX_ACTOR_WRITER_BYTES / 2 + 1))),
            Err(ActorError::WriterTooLong)
        );
    }

    #[test]
    fn test_actor_debug_redacts_user_id() {
        let debug = format!("{:?}", actor(Some("secret-user"), Some("ui")));
        assert!(!debug.contains("secret-user"), "{debug}");
        assert!(debug.contains("ui"), "{debug}");
    }
}
