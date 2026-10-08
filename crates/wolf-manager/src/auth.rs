use std::net::IpAddr;
use wolf_core::*;
pub fn admit_ingress(peer: IpAddr) -> Result<(), SafeError> {
    if peer.to_canonical() != IpAddr::from([172, 30, 32, 2]) {
        return Err(SafeError::new("ingress_peer_forbidden"));
    }
    Ok(())
}
pub fn normalize_origin(value: &str) -> Result<String, SafeError> {
    if value.len() > 512
        || value
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
    {
        return Err(SafeError::validation());
    }
    let authority = value.split_once("://").ok_or_else(SafeError::validation)?.1;
    if authority.contains(['@', '\\'])
        || authority
            .split_once('/')
            .is_some_and(|(_, path)| !path.is_empty())
    {
        return Err(SafeError::validation());
    }
    let url = url::Url::parse(value).map_err(|_| SafeError::validation())?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(SafeError::validation());
    }
    Ok(url.origin().ascii_serialization())
}
use crate::{
    protected::internal,
    store::{Store, hash},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHasher, PasswordVerifier, phc::PasswordHash},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use std::{fs::File, io::Read, os::unix::fs::MetadataExt};
const MINUTE: i64 = 60_000;
const IDLE: i64 = 12 * 60 * MINUTE;
const ABSOLUTE: i64 = 7 * 24 * 60 * MINUTE;
#[derive(Clone, Copy)]
pub enum Purpose {
    Login,
    Bootstrap,
}
impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::Bootstrap => "bootstrap",
        }
    }
}
pub struct BootstrapSecret {
    digest: Vec<u8>,
}
impl BootstrapSecret {
    pub fn read(path: &std::path::Path) -> Result<Self, SafeError> {
        let fd = rustix::fs::openat2(
            rustix::fs::CWD,
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
            rustix::fs::ResolveFlags::NO_SYMLINKS | rustix::fs::ResolveFlags::NO_MAGICLINKS,
        )
        .map_err(internal)?;
        let file = File::from(fd);
        let meta = file.metadata().map_err(internal)?;
        if !meta.is_file()
            || meta.nlink() != 1
            || meta.mode() & 0o077 != 0
            || ![0, rustix::process::geteuid().as_raw()].contains(&meta.uid())
        {
            return Err(SafeError::new("forbidden"));
        }
        let mut bytes = Vec::new();
        file.take(1025).read_to_end(&mut bytes).map_err(internal)?;
        while bytes.last().is_some_and(|b| matches!(b, b'\n' | b'\r')) {
            bytes.pop();
        }
        if !(32..=1024).contains(&bytes.len()) {
            return Err(SafeError::validation());
        }
        Ok(Self {
            digest: hash(&bytes),
        })
    }
}
pub struct Challenge {
    pub token: String,
    pub expires_at: i64,
}
pub struct SessionCredentials {
    pub session_token: String,
    pub csrf_token: String,
    pub expires_at: i64,
}
impl SessionCredentials {
    pub fn cookie(&self) -> String {
        format!(
            "__Host-wolf_session={}; Secure; HttpOnly; SameSite=Strict; Path=/",
            self.session_token
        )
    }
}
pub struct LoginAttempt<'a> {
    pub peer: IpAddr,
    pub origin: &'a str,
    pub challenge: &'a str,
    pub csrf_header: &'a str,
    pub password: &'a str,
}
pub struct SessionInfo {
    pub expires_at: i64,
    pub absolute_expires_at: i64,
}
enum Mode {
    Standalone {
        origin: String,
        bootstrap: BootstrapSecret,
    },
    Ingress,
}
pub struct AuthService<'a> {
    store: &'a mut Store,
    mode: Mode,
}
fn token() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    let mut bits = 0u32;
    let mut available = 0;
    for byte in bytes {
        bits = (bits << 8) | u32::from(byte);
        available += 8;
        while available >= 6 {
            available -= 6;
            output.push(alphabet[((bits >> available) & 63) as usize] as char);
        }
    }
    if available > 0 {
        output.push(alphabet[((bits << (6 - available)) & 63) as usize] as char);
    }
    output
}
fn valid_token(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
pub(crate) fn hash_password(password: &str) -> Result<String, SafeError> {
    if !(12..=1024).contains(&password.len()) {
        return Err(SafeError::validation());
    }
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|h| h.to_string())
        .map_err(internal)
}
fn verify_password(password: &str, stored: &str) -> bool {
    if password.len() > 1024 {
        return false;
    }
    PasswordHash::new(stored)
        .ok()
        .filter(|h| {
            h.algorithm.as_str() == "argon2id"
                && h.version == Some(19)
                && h.params
                    .get_decimal("m")
                    .is_some_and(|m| (8..=65536).contains(&m))
                && h.params
                    .get_decimal("t")
                    .is_some_and(|t| (1..=10).contains(&t))
                && h.params
                    .get_decimal("p")
                    .is_some_and(|p| (1..=4).contains(&p))
        })
        .is_some_and(|h| {
            Argon2::default()
                .verify_password(password.as_bytes(), &h)
                .is_ok()
        })
}
fn constant_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |diff, (a, b)| diff | (a ^ b)) == 0
}
impl<'a> AuthService<'a> {
    pub fn standalone(
        store: &'a mut Store,
        origin: &str,
        bootstrap: BootstrapSecret,
    ) -> Result<Self, SafeError> {
        let origin = normalize_origin(origin)?;
        if !origin.starts_with("https://") {
            return Err(SafeError::new("forbidden"));
        }
        Ok(Self {
            store,
            mode: Mode::Standalone { origin, bootstrap },
        })
    }
    pub fn ingress(store: &'a mut Store) -> Self {
        Self {
            store,
            mode: Mode::Ingress,
        }
    }
    fn standalone_origin(&self) -> Result<&str, SafeError> {
        match &self.mode {
            Mode::Standalone { origin, .. } => Ok(origin),
            Mode::Ingress => Err(SafeError::new("forbidden")),
        }
    }
    fn check_origin(&self, origin: &str) -> Result<(), SafeError> {
        if normalize_origin(origin).map_err(|_| SafeError::new("csrf_failed"))?
            != self.standalone_origin()?
        {
            return Err(SafeError::new("csrf_failed"));
        }
        Ok(())
    }
    fn check_time(&self, now: i64) -> Result<(), SafeError> {
        self.store.root.verify()?;
        if !(0..=i64::MAX - ABSOLUTE).contains(&now) {
            return Err(SafeError::validation());
        }
        Ok(())
    }
    pub fn initialized(&self) -> Result<bool, SafeError> {
        self.standalone_origin()?;
        self.store.root.verify()?;
        Ok(self.store.root.marker_present()?
            || self
                .store
                .conn
                .query_row("SELECT EXISTS(SELECT 1 FROM administrator)", [], |r| {
                    r.get(0)
                })
                .map_err(internal)?)
    }
    pub fn issue_challenge(
        &mut self,
        peer: IpAddr,
        purpose: Purpose,
        now: i64,
    ) -> Result<Challenge, SafeError> {
        self.standalone_origin()?;
        self.check_time(now)?;
        if matches!(purpose, Purpose::Bootstrap) && self.initialized()? {
            return Err(SafeError::new("bootstrap_completed"));
        }
        self.store.conn.execute("DELETE FROM login_challenges WHERE expires_at_ms<=?1 OR consumed_at_ms IS NOT NULL",[now]).map_err(internal)?;
        let peer = peer.to_canonical().to_string();
        let (total, per_peer): (i64, i64) = self
            .store
            .conn
            .query_row(
                "SELECT count(*),sum(CASE WHEN peer_ip=?1 THEN 1 ELSE 0 END) FROM login_challenges",
                [&peer],
                |r| Ok((r.get(0)?, r.get::<_, Option<i64>>(1)?.unwrap_or(0))),
            )
            .map_err(internal)?;
        if total >= 1024 || per_peer >= 8 {
            return Err(SafeError::new("login_rate_limited"));
        }
        let value = token();
        let expires = now + 5 * MINUTE;
        self.store
            .conn
            .execute(
                "INSERT INTO login_challenges VALUES(?1,?2,?3,?4,NULL)",
                params![hash(value.as_bytes()), peer, purpose.as_str(), expires],
            )
            .map_err(internal)?;
        Ok(Challenge {
            token: value,
            expires_at: expires,
        })
    }
    fn consume_challenge(
        &mut self,
        attempt: &LoginAttempt<'_>,
        purpose: Purpose,
        now: i64,
    ) -> Result<(), SafeError> {
        if !valid_token(attempt.challenge)
            || !constant_equal(attempt.challenge.as_bytes(), attempt.csrf_header.as_bytes())
        {
            return Err(SafeError::new("csrf_failed"));
        }
        let changed=self.store.conn.execute("UPDATE login_challenges SET consumed_at_ms=?1 WHERE challenge_digest=?2 AND peer_ip=?3 AND purpose=?4 AND expires_at_ms>?1 AND consumed_at_ms IS NULL",params![now,hash(attempt.challenge.as_bytes()),attempt.peer.to_canonical().to_string(),purpose.as_str()]).map_err(internal)?;
        if changed != 1 {
            return Err(SafeError::new("csrf_failed"));
        }
        Ok(())
    }
    pub fn bootstrap(
        &mut self,
        attempt: LoginAttempt<'_>,
        bearer: &str,
        now: i64,
    ) -> Result<SessionCredentials, SafeError> {
        self.check_time(now)?;
        self.check_origin(attempt.origin)?;
        if self.initialized()? {
            return Err(SafeError::new("bootstrap_completed"));
        }
        self.consume_challenge(&attempt, Purpose::Bootstrap, now)?;
        let Mode::Standalone { bootstrap, .. } = &self.mode else {
            return Err(SafeError::new("forbidden"));
        };
        if bearer.len() > 1024 || !constant_equal(&bootstrap.digest, &hash(bearer.as_bytes())) {
            return Err(SafeError::new("invalid_bootstrap_token"));
        }
        let password = hash_password(attempt.password)?;
        // Persist the fail-closed marker first. A failed SQL transaction then
        // requires offline recovery and cannot silently reopen bootstrap.
        self.store.root.initialize_marker()?;
        let session = token();
        let csrf = token();
        let tx = self
            .store
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(internal)?;
        tx.execute(
            "INSERT INTO administrator VALUES(1,?1,?2,?2)",
            params![password, now],
        )
        .map_err(internal)?;
        tx.execute(
            "INSERT INTO sessions VALUES(?1,?2,?3,?3,?4,?5,NULL)",
            params![
                hash(session.as_bytes()),
                hash(csrf.as_bytes()),
                now,
                now + IDLE,
                now + ABSOLUTE
            ],
        )
        .map_err(internal)?;
        tx.commit().map_err(internal)?;
        Ok(SessionCredentials {
            session_token: session,
            csrf_token: csrf,
            expires_at: now + IDLE,
        })
    }
    pub fn login(
        &mut self,
        attempt: LoginAttempt<'_>,
        now: i64,
    ) -> Result<SessionCredentials, SafeError> {
        self.check_time(now)?;
        self.check_origin(attempt.origin)?;
        self.consume_challenge(&attempt, Purpose::Login, now)?;
        let peer = attempt.peer.to_canonical().to_string();
        self.store
            .conn
            .execute(
                "DELETE FROM login_failures WHERE window_started_at_ms<=?1",
                [now - 15 * MINUTE],
            )
            .map_err(internal)?;
        let count: i64 = self
            .store
            .conn
            .query_row(
                "SELECT failures FROM login_failures WHERE peer_ip=?1",
                [&peer],
                |r| r.get(0),
            )
            .optional()
            .map_err(internal)?
            .unwrap_or(0);
        if count >= 5 {
            return Err(SafeError::new("login_rate_limited"));
        }
        let stored: Option<String> = self
            .store
            .conn
            .query_row(
                "SELECT password_hash FROM administrator WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(internal)?;
        if !stored
            .as_ref()
            .is_some_and(|hash| verify_password(attempt.password, hash))
        {
            let total: i64 = self
                .store
                .conn
                .query_row("SELECT count(*) FROM login_failures", [], |r| r.get(0))
                .map_err(internal)?;
            if count == 0 && total >= 10000 {
                return Err(SafeError::new("login_rate_limited"));
            }
            self.store.conn.execute("INSERT INTO login_failures VALUES(?1,?2,1) ON CONFLICT(peer_ip) DO UPDATE SET failures=failures+1",params![peer,now]).map_err(internal)?;
            return Err(SafeError::new("login_failed"));
        }
        self.store
            .conn
            .execute("DELETE FROM login_failures WHERE peer_ip=?1", [peer])
            .map_err(internal)?;
        self.issue_session(now)
    }
    fn issue_session(&mut self, now: i64) -> Result<SessionCredentials, SafeError> {
        self.store.conn.execute("DELETE FROM sessions WHERE revoked_at_ms IS NOT NULL OR idle_expires_at_ms<=?1 OR absolute_expires_at_ms<=?1",[now]).map_err(internal)?;
        let count: i64 = self
            .store
            .conn
            .query_row("SELECT count(*) FROM sessions", [], |r| r.get(0))
            .map_err(internal)?;
        if count >= 2048 {
            return Err(SafeError::new("login_rate_limited"));
        }
        let session = token();
        let csrf = token();
        self.store
            .conn
            .execute(
                "INSERT INTO sessions VALUES(?1,?2,?3,?3,?4,?5,NULL)",
                params![
                    hash(session.as_bytes()),
                    hash(csrf.as_bytes()),
                    now,
                    now + IDLE,
                    now + ABSOLUTE
                ],
            )
            .map_err(internal)?;
        Ok(SessionCredentials {
            session_token: session,
            csrf_token: csrf,
            expires_at: now + IDLE,
        })
    }
    pub fn authenticate(&mut self, session: &str, now: i64) -> Result<SessionInfo, SafeError> {
        self.standalone_origin()?;
        self.check_time(now)?;
        if !valid_token(session) {
            return Err(SafeError::new("unauthenticated"));
        }
        let expires:Option<i64>=self.store.conn.query_row("SELECT absolute_expires_at_ms FROM sessions WHERE token_digest=?1 AND revoked_at_ms IS NULL AND idle_expires_at_ms>?2 AND absolute_expires_at_ms>?2",params![hash(session.as_bytes()),now],|r|r.get(0)).optional().map_err(internal)?;
        let absolute = expires.ok_or_else(|| SafeError::new("unauthenticated"))?;
        let idle = (now + IDLE).min(absolute);
        self.store.conn.execute("UPDATE sessions SET last_seen_at_ms=?1,idle_expires_at_ms=?2 WHERE token_digest=?3",params![now,idle,hash(session.as_bytes())]).map_err(internal)?;
        Ok(SessionInfo {
            expires_at: idle,
            absolute_expires_at: absolute,
        })
    }
    pub fn require_mutation(
        &mut self,
        session: &str,
        csrf: &str,
        origin: &str,
        now: i64,
    ) -> Result<(), SafeError> {
        self.check_origin(origin)?;
        self.authenticate(session, now)?;
        if !valid_token(csrf) {
            return Err(SafeError::new("csrf_failed"));
        }
        let valid: bool = self
            .store
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sessions WHERE token_digest=?1 AND csrf_digest=?2)",
                params![hash(session.as_bytes()), hash(csrf.as_bytes())],
                |r| r.get(0),
            )
            .map_err(internal)?;
        if !valid {
            return Err(SafeError::new("csrf_failed"));
        }
        Ok(())
    }
    pub fn issue_session_csrf(&mut self, session: &str, now: i64) -> Result<Challenge, SafeError> {
        let info = self.authenticate(session, now)?;
        let value = token();
        self.store
            .conn
            .execute(
                "UPDATE sessions SET csrf_digest=?1 WHERE token_digest=?2",
                params![hash(value.as_bytes()), hash(session.as_bytes())],
            )
            .map_err(internal)?;
        Ok(Challenge {
            token: value,
            expires_at: info.expires_at,
        })
    }
    pub fn logout(
        &mut self,
        session: &str,
        csrf: &str,
        origin: &str,
        now: i64,
    ) -> Result<(), SafeError> {
        self.require_mutation(session, csrf, origin, now)?;
        self.store
            .conn
            .execute(
                "UPDATE sessions SET revoked_at_ms=?1 WHERE token_digest=?2",
                params![now, hash(session.as_bytes())],
            )
            .map_err(internal)?;
        Ok(())
    }
    pub fn change_password(
        &mut self,
        session: &str,
        csrf: &str,
        origin: &str,
        current: &str,
        new: &str,
        now: i64,
    ) -> Result<(), SafeError> {
        self.require_mutation(session, csrf, origin, now)?;
        let stored: String = self
            .store
            .conn
            .query_row(
                "SELECT password_hash FROM administrator WHERE id=1",
                [],
                |r| r.get(0),
            )
            .map_err(internal)?;
        if !verify_password(current, &stored) {
            return Err(SafeError::new("login_failed"));
        }
        let new = hash_password(new)?;
        let tx = self.store.conn.transaction().map_err(internal)?;
        tx.execute(
            "UPDATE administrator SET password_hash=?1,updated_at_ms=?2 WHERE id=1",
            params![new, now],
        )
        .map_err(internal)?;
        tx.execute(
            "UPDATE sessions SET revoked_at_ms=?1 WHERE revoked_at_ms IS NULL",
            [now],
        )
        .map_err(internal)?;
        tx.commit().map_err(internal)
    }
    pub fn issue_ingress_csrf(
        &mut self,
        peer: IpAddr,
        origin: &str,
        now: i64,
    ) -> Result<Challenge, SafeError> {
        if !matches!(self.mode, Mode::Ingress) {
            return Err(SafeError::new("forbidden"));
        }
        admit_ingress(peer)?;
        self.check_time(now)?;
        let origin = normalize_origin(origin)?;
        self.store
            .conn
            .execute(
                "DELETE FROM ingress_csrf_tokens WHERE expires_at_ms<=?1",
                [now],
            )
            .map_err(internal)?;
        let count: i64 = self
            .store
            .conn
            .query_row("SELECT count(*) FROM ingress_csrf_tokens", [], |r| r.get(0))
            .map_err(internal)?;
        if count >= 1024 {
            return Err(SafeError::new("login_rate_limited"));
        }
        let value = token();
        let expires = now + 30 * MINUTE;
        self.store
            .conn
            .execute(
                "INSERT INTO ingress_csrf_tokens VALUES(?1,?2,?3)",
                params![hash(value.as_bytes()), origin, expires],
            )
            .map_err(internal)?;
        Ok(Challenge {
            token: value,
            expires_at: expires,
        })
    }
    pub fn require_ingress_mutation(
        &mut self,
        peer: IpAddr,
        csrf: &str,
        origin: &str,
        now: i64,
    ) -> Result<(), SafeError> {
        if !matches!(self.mode, Mode::Ingress) {
            return Err(SafeError::new("forbidden"));
        }
        admit_ingress(peer)?;
        self.check_time(now)?;
        let origin = normalize_origin(origin).map_err(|_| SafeError::new("csrf_failed"))?;
        if !valid_token(csrf) {
            return Err(SafeError::new("csrf_failed"));
        }
        let valid:bool=self.store.conn.query_row("SELECT EXISTS(SELECT 1 FROM ingress_csrf_tokens WHERE token_digest=?1 AND origin=?2 AND expires_at_ms>?3)",params![hash(csrf.as_bytes()),origin,now],|r|r.get(0)).map_err(internal)?;
        if !valid {
            return Err(SafeError::new("csrf_failed"));
        }
        Ok(())
    }
}
#[derive(Clone)]
pub enum TransportPolicy {
    Ingress,
    NativeTls,
    TrustedProxy(Vec<IpAddr>),
}
impl TransportPolicy {
    pub fn admit(&self, peer: IpAddr) -> Result<(), SafeError> {
        match self {
            Self::Ingress => admit_ingress(peer),
            Self::NativeTls => Ok(()),
            Self::TrustedProxy(peers) => {
                if peers
                    .iter()
                    .any(|allowed| allowed.to_canonical() == peer.to_canonical())
                {
                    Ok(())
                } else {
                    Err(SafeError::new("forbidden"))
                }
            }
        }
    }
}
pub fn normalize_ingress_prefix(value: &str) -> Result<String, SafeError> {
    if value == "/" {
        return Ok(value.into());
    }
    if !value.starts_with('/')
        || value.len() > 1024
        || value.contains("//")
        || value[1..].trim_end_matches('/').split('/').any(|part| {
            part.is_empty()
                || part == "."
                || part == ".."
                || !part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        })
    {
        return Err(SafeError::validation());
    }
    Ok(if value.ends_with('/') {
        value.into()
    } else {
        format!("{value}/")
    })
}
