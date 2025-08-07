use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::client::ClientError;
use anyhow::Result;
use bytes::Bytes;
use hyper::{
    HeaderMap,
    header::{self, HeaderValue},
};
use reqwest::{Client, redirect::Policy};
use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone)]
pub struct KeycloakConfig {
    pub realm_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub username: String,
    pub password: String,
    pub scope: Option<String>,
}

impl KeycloakConfig {
    pub fn new(
        realm_url: String,
        client_id: String,
        client_secret: Option<String>,
        username: String,
        password: String,
        scope: Option<String>,
    ) -> Self {
        Self {
            realm_url,
            client_id,
            client_secret,
            username,
            password,
            scope,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    refresh_token: Option<String>,
    token_type: String,
}

pub struct KeycloakAuth {
    config: KeycloakConfig,
    access_token: Arc<Mutex<Option<String>>>,
    expires_at: Arc<Mutex<Option<Instant>>>,
    refresh_token: Arc<Mutex<Option<String>>>,
    client: Client,
}

impl KeycloakAuth {
    pub fn new(config: KeycloakConfig) -> Self {
        let client = Client::builder()
            .redirect(Policy::none()) // Don't follow redirects automatically
            .build()
            .expect("Failed to create HTTP client");

        Self {
            config,
            access_token: Arc::new(Mutex::new(None)),
            expires_at: Arc::new(Mutex::new(None)),
            refresh_token: Arc::new(Mutex::new(None)),
            client,
        }
    }

    /// Authenticate using the Resource Owner Password Credentials Grant
    pub async fn authenticate(&self) -> Result<(), ClientError> {
        let token_url = format!("{}/protocol/openid-connect/token", self.config.realm_url);

        let mut params = HashMap::new();
        params.insert("grant_type", "password");
        params.insert("client_id", &self.config.client_id);
        params.insert("username", &self.config.username);
        params.insert("password", &self.config.password);

        if let Some(client_secret) = &self.config.client_secret {
            params.insert("client_secret", client_secret);
        }

        let scope = self.config.scope.as_deref().unwrap_or("openid");
        params.insert("scope", scope);

        println!("About to post response to {} :3", &token_url);

        let response = self.client.post(&token_url).form(&params).send().await?;

        if !response.status().is_success() {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            return Err(ClientError::AuthenticationError(error_text));
        }

        let token_response: TokenResponse = response.json().await.map_err(ClientError::Reqwest)?;

        let expires_at = Instant::now() + Duration::from_secs(token_response.expires_in);

        *self.access_token.lock().unwrap() = Some(token_response.access_token);
        *self.expires_at.lock().unwrap() = Some(expires_at);
        *self.refresh_token.lock().unwrap() = token_response.refresh_token;

        Ok(())
    }

    /// Refresh the access token using the refresh token
    pub async fn refresh_token(&self) -> Result<(), ClientError> {
        let refresh_token = {
            let token = self.refresh_token.lock().unwrap();
            token.as_ref().cloned()
        };

        let refresh_token = match refresh_token {
            Some(t) => t,
            None => return self.authenticate().await, // Fall back to re-authentication
        };

        let token_url = format!("{}/protocol/openid-connect/token", self.config.realm_url);

        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("client_id", &self.config.client_id);
        params.insert("refresh_token", &refresh_token);

        if let Some(client_secret) = &self.config.client_secret {
            params.insert("client_secret", client_secret);
        }

        let response = self
            .client
            .post(&token_url)
            .form(&params)
            .send()
            .await
            .map_err(ClientError::Reqwest)?;

        if !response.status().is_success() {
            // If refresh fails, try to re-authenticate
            return self.authenticate().await;
        }

        let token_response: TokenResponse = response.json().await.map_err(ClientError::Reqwest)?;

        let expires_at = Instant::now() + Duration::from_secs(token_response.expires_in);

        *self.access_token.lock().unwrap() = Some(token_response.access_token);
        *self.expires_at.lock().unwrap() = Some(expires_at);
        if let Some(new_refresh_token) = token_response.refresh_token {
            *self.refresh_token.lock().unwrap() = Some(new_refresh_token);
        }

        Ok(())
    }

    /// Get a valid access token, refreshing if necessary
    async fn get_valid_token(&self) -> Result<String, ClientError> {
        let (token, expires_at) = {
            let token = self.access_token.lock().unwrap();
            let expires = self.expires_at.lock().unwrap();
            (token.clone(), *expires)
        };

        match (token, expires_at) {
            (Some(token), Some(expires)) if Instant::now() + Duration::from_secs(30) < expires => {
                // Token is valid and has at least 30 seconds left
                Ok(token)
            }
            _ => {
                // Token is expired or doesn't exist, need to refresh or authenticate
                if self.refresh_token.lock().unwrap().is_some() {
                    self.refresh_token().await?;
                } else {
                    self.authenticate().await?;
                }

                self.access_token.lock().unwrap().clone().ok_or_else(|| {
                    ClientError::AuthenticationError("Failed to obtain access token".into())
                })
            }
        }
    }

    /// Sign a request with the Bearer token
    pub async fn sign_request(
        &self,
        _method: &str,
        headers: &mut HeaderMap,
        _url: &Url,
        _body: &Option<Bytes>,
    ) -> Result<(), ClientError> {
        let token = self.get_valid_token().await?;
        let auth_value = format!("Bearer {token}");
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&auth_value).map_err(|_| {
                ClientError::AuthenticationError("Invalid token format".to_string())
            })?,
        );
        Ok(())
    }

    /// Perform initial authentication for CLI setup
    pub async fn initial_auth(&self) -> Result<String, ClientError> {
        self.authenticate().await?;
        self.get_valid_token().await
    }
}

/// Parse Keycloak configuration from command line string
/// Format: "realm_url|client_id|username|password" or "realm_url|client_id|client_secret|username|password"
pub fn parse_keycloak_config(config_str: &str) -> Result<KeycloakConfig, anyhow::Error> {
    let parts: Vec<&str> = config_str.split('|').collect();

    match parts.len() {
        4 => {
            // Format: realm_url|client_id|username|password (no client secret)
            Ok(KeycloakConfig::new(
                parts[0].to_string(),
                parts[1].to_string(),
                None,
                parts[2].to_string(),
                parts[3].to_string(),
                Some("openid".to_string()),
            ))
        }
        5 => {
            // Format: realm_url|client_id|client_secret|username|password
            Ok(KeycloakConfig::new(
                parts[0].to_string(),
                parts[1].to_string(),
                Some(parts[2].to_string()),
                parts[3].to_string(),
                parts[4].to_string(),
                Some("openid".to_string()),
            ))
        }
        _ => anyhow::bail!(
            "Invalid Keycloak config format. Expected 'realm_url|client_id|username|password' or 'realm_url|client_id|client_secret|username|password', got {} parts",
            parts.len()
        ),
    }
}
