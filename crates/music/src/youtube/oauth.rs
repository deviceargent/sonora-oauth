use std::path::PathBuf;

use anyhow::{Context as _, Result};
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope,
    TokenResponse as _, TokenUrl, basic::BasicClient,
};
use serde::{Deserialize, Serialize};

use crate::credentials;

const CLIENT_ID: &str = "861543794000-8o9nqj3f3f9d0v5p5c6m7r8t9u0v1w2x.apps.googleusercontent.com";
const REDIRECT_URI: &str = "http://localhost:8989/youtube/callback";
const SCOPES: &[&str] = &["https://www.googleapis.com/auth/youtube.readonly"];

#[derive(Debug, Serialize, Deserialize)]
pub struct Saved {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
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

pub async fn login(config: &OAuthConfig) -> Result<Saved> {
    let client = BasicClient::new(ClientId::new(CLIENT_ID.to_owned()))
        .set_auth_uri(AuthUrl::new(
            "https://accounts.google.com/o/oauth2/v2/auth".to_owned(),
        )?)
        .set_token_uri(TokenUrl::new(
            "https://oauth2.googleapis.com/token".to_owned(),
        )?)
        .set_redirect_uri(RedirectUrl::new(REDIRECT_URI.to_owned())?);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let scopes = SCOPES.iter().map(|scope| Scope::new((*scope).to_owned()));
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scopes(scopes)
        .set_pkce_challenge(pkce_challenge)
        .url();

    println!("Open this URL in your browser: {}", auth_url);
    println!("Paste the authorization code here:");

    let mut code = String::new();
    std::io::stdin().read_line(&mut code)?;
    let code = code.trim();

    let token_response = client
        .exchange_code(AuthorizationCode::new(code.to_owned()))
        .set_pkce_verifier(pkce_verifier)
        .request_async(&http_client)
        .await
        .context("Failed to exchange code")?;

    let saved = Saved {
        access_token: token_response.access_token().secret().to_owned(),
        refresh_token: token_response
            .refresh_token()
            .map(|t| t.secret().to_owned())
            .unwrap_or_default(),
        token_type: token_response.token_type().as_str().to_owned(),
    };

    save(config, &saved)?;
    Ok(saved)
}

pub fn save(config: &OAuthConfig, saved: &Saved) -> Result<()> {
    let body = serde_json::to_vec_pretty(saved).context("Cannot encode OAuth2 credentials")?;
    credentials::write(&config.file(), &body)
}

pub fn load(config: &OAuthConfig) -> Option<Saved> {
    let body = std::fs::read(config.file()).ok()?;
    serde_json::from_slice(&body).ok()
}

async fn http_client(request: oauth2::HttpRequest) -> Result<oauth2::HttpResponse, oauth2::reqwest::Error> {
    let client = reqwest::Client::new();
    let response = client
        .execute(request.try_into()?)
        .await
        .map_err(oauth2::reqwest::Error::from)?;

    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.map_err(oauth2::reqwest::Error::from)?;

    let mut http_response = http::Response::new(body.to_vec());
    *http_response.status_mut() = status;
    *http_response.headers_mut() = headers;

    Ok(http_response)
}