use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;
use std::path::PathBuf;

use anyhow::{Context as _, Result, anyhow};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, EmptyExtraTokenFields, PkceCodeChallenge,
    RedirectUrl, Scope, StandardTokenResponse, TokenResponse as _, TokenUrl, basic::BasicClient,
};
use serde::{Deserialize, Serialize};

use crate::credentials;

/// Desktop client id registered for Sonora's YouTube sign-in.
const CLIENT_ID: &str = "861543794000-8o9nqj3f3f9d0v5p5c6m7r8t9u0v1w2x.apps.googleusercontent.com";
const REDIRECT_URI: &str = "http://127.0.0.1:8989/youtube/callback";
const SCOPES: &[&str] = &["https://www.googleapis.com/auth/youtube.readonly"];

/// A persisted Google OAuth2 grant: the refresh token is what survives restarts.
#[derive(Debug, Serialize, Deserialize)]
pub struct Saved {
    pub refresh_token: String,
}

pub struct OAuthConfig {
    pub cache_dir: PathBuf,
}

impl OAuthConfig {
    pub fn new() -> Self {
        Self {
            cache_dir: credentials::dir("youtube"),
        }
    }

    pub fn file(&self) -> PathBuf {
        self.cache_dir.join("oauth.json")
    }
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs the authorization-code + PKCE flow: opens the browser, listens for the
/// loopback redirect and exchanges the code. Blocking; call via spawn_blocking.
pub fn login(config: &OAuthConfig) -> Result<Saved> {
    let (verifier, url) = authorize_url()?;
    open::that_in_background(url.as_str());

    let address = socket_address(REDIRECT_URI).context("redirect URI has no socket address")?;
    let listener = TcpListener::bind(&address)
        .with_context(|| format!("cannot listen for Google login at {address}"))?;
    let mut stream = listener
        .incoming()
        .next()
        .context("Google login callback did not arrive")??;
    let mut request = String::new();
    BufReader::new(&stream).read_line(&mut request)?;
    let target = request
        .split_whitespace()
        .nth(1)
        .context("Google login callback was malformed")?;
    let callback = oauth2::url::Url::parse(&format!("http://localhost{target}"))?;
    let response = "You can return to Sonora.";
    write!(
        stream,
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n{response}",
        response.len()
    )?;

    let query: std::collections::HashMap<_, _> = callback.query_pairs().collect();
    if let Some(error) = query.get("error") {
        anyhow::bail!("google login failed: {error}");
    }
    let code = query
        .get("code")
        .context("Google login callback had no authorization code")?;

    let client = BasicClient::new(ClientId::new(CLIENT_ID.to_owned()))
        .set_auth_uri(AuthUrl::new(
            "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
        )?)
        .set_token_uri(TokenUrl::new("https://oauth2.googleapis.com/token".to_owned())?)
        .set_redirect_uri(RedirectUrl::new(REDIRECT_URI.to_owned())?);
    let token: StandardTokenResponse<EmptyExtraTokenFields, _> = client
        .exchange_code(AuthorizationCode::new(code.to_string()))
        .set_pkce_verifier(verifier)
        .request(&exchange)
        .map_err(|error| anyhow!("failed to exchange Google authorization code: {error}"))?;

    let saved = Saved {
        refresh_token: token
            .refresh_token()
            .map(|t| t.secret().to_owned())
            .context("Google did not return a refresh token")?,
    };
    save(config, &saved)?;
    Ok(saved)
}

fn authorize_url() -> Result<(oauth2::PkceCodeVerifier, oauth2::url::Url)> {
    let client = BasicClient::new(ClientId::new(CLIENT_ID.to_owned()))
        .set_auth_uri(AuthUrl::new(
            "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
        )?)
        .set_token_uri(TokenUrl::new("https://oauth2.googleapis.com/token".to_owned())?)
        .set_redirect_uri(RedirectUrl::new(REDIRECT_URI.to_owned())?);
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let scopes = SCOPES.iter().map(|scope| Scope::new((*scope).to_owned()));
    let (url, _) = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes)
        .set_pkce_challenge(challenge)
        .add_extra_param("access_type", "offline")
        .url();
    Ok((verifier, url))
}

fn socket_address(uri: &str) -> Option<String> {
    let rest = uri
        .strip_prefix("http://")
        .or_else(|| uri.strip_prefix("https://"))?;
    let authority = rest.split('/').next().filter(|host| !host.is_empty())?;
    match authority.rsplit_once(':') {
        Some((_, port)) if port.chars().all(|digit| digit.is_ascii_digit()) => {
            Some(authority.to_owned())
        }
        _ => Some(format!("{authority}:80")),
    }
}

/// Carries one oauth2 request over reqwest. oauth2 only knows the reqwest it was built
/// against, so the workspace one is handed in as a plain function instead.
fn exchange(request: oauth2::HttpRequest) -> Result<oauth2::HttpResponse, reqwest::Error> {
    let sent = reqwest::blocking::Client::new().execute(request.try_into()?)?;
    let status = sent.status();
    let headers = sent.headers().clone();
    let mut response = http::Response::new(sent.bytes()?.to_vec());
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    Ok(response)
}

pub fn save(config: &OAuthConfig, saved: &Saved) -> Result<()> {
    let body = serde_json::to_vec_pretty(saved).context("cannot encode OAuth2 credentials")?;
    credentials::write(&config.file(), &body)
}

pub fn load(config: &OAuthConfig) -> Option<Saved> {
    let body = std::fs::read(config.file()).ok()?;
    serde_json::from_slice(&body).ok()
}

pub fn forget(config: &OAuthConfig) {
    credentials::remove(&config.file());
}
