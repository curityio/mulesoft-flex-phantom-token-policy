// Inspired by the introspection example from the Mulesoft documentation

mod generated;
mod jwt;

use jwt::{decode_jwt};
use anyhow::{anyhow, Result};
use crate::generated::config::Config;
use pdk::hl::*;
use pdk::logger;
use pdk::script::{HandlerAttributesBinding, TryFromValue};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Deserialize};
use base64::{engine::general_purpose, Engine};

#[derive(Debug)]
pub enum FilterError {
    Unexpected,
    NoToken,
    InactiveToken,
    ExpiredToken,
    NotYetActive,
    ClientError(HttpClientError),
    NonParsableIntrospectionBody(String),
    MissingScope,
    InvalidToken,
    ParseJwt(String),
    WrongAud,
    WrongIss,
}

#[derive(Deserialize)]
struct IntrospectionResponse {
    exp: Option<u64>,
    nbf: Option<u64>,
    scope: String,
    active: bool,
    phantom_token: String,
    iss: String,
    aud: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    exp: Option<u64>,
    nbf: Option<u64>,
    scope: String,
    aud: String,
    iss: String,
}

/// Sends the request to the introspection endpoint and parse the response
async fn introspect_token(
    token: &str,
    config: &Config,
    client: HttpClient,
) -> Result<IntrospectionResponse, FilterError> {
    logger::debug!("Introspecting token");

    // Encodes the token for the request payload
    let body = serde_urlencoded::to_string([("token", token)]).map_err(|_| FilterError::Unexpected)?;

    let authorization_string = format!("{}:{}", config.introspection_client.as_str(), config.introspection_secret.as_str());
    let authorization = general_purpose::STANDARD.encode(authorization_string);
    let authorization_header = format!("Basic {}", authorization);

    let headers = if config.use_application_jwt_header {
        logger::debug!("Introspecting access token using 'application/jwt' header");
        vec![
            ("content-type", "application/x-www-form-urlencoded"),
            ("Authorization", authorization_header.as_str()),
            ("Accept", "application/jwt")
        ]
    } else {
        logger::debug!("Introspecting access token using phantom_token claim");
        vec![
            ("content-type", "application/x-www-form-urlencoded"),
            ("Authorization", authorization_header.as_str()),
        ]
    };

    // Send request to introspection endpoint
    let response = client
        .request(&config.introspection_endpoint)
        .headers(headers)
        .body(body.as_bytes())
        .post()
        .await
        .map_err(FilterError::ClientError)?;

    if response.status_code() == 200 {
        //If 'application/jwt' header is used, decode the JWT and return the claims
        if config.use_application_jwt_header {
            let jwt = response.body();
            let jwt_str = std::str::from_utf8(jwt).unwrap();

            match decode_jwt(jwt_str) {
                Ok(claims) => {
                    return Ok(IntrospectionResponse {
                        active: true, // Response form introspection indicates token is active
                        exp: claims.exp,
                        nbf: claims.nbf,
                        scope: claims.scope,
                        phantom_token: jwt_str.to_string(), // passing the JWT in the phantom_token attribute
                        iss: claims.iss,
                        aud: claims.aud,
                    });
                }
                Err(_err) => {
                    return Err(FilterError::NonParsableIntrospectionBody(("Error decoding JWT").to_string())); // Early return on JWT decode failure
                }
            }
        }

        // If 'application/jwt' header is NOT used, return the introspection response
        serde_json::from_slice(response.body()).map_err(|err| FilterError::NonParsableIntrospectionBody(err.to_string()))
    } else if response.status_code() == 204 {
        logger::debug!("Token not active");
        Err(FilterError::InactiveToken)
    } else {
        Err(FilterError::InactiveToken)
    }
}

async fn do_filter(
    headers_state: &RequestHeadersState,
    config: &Config,
    client: HttpClient,
) -> Result<IntrospectionResponse, FilterError> {

    // Extracts the token from the request
    let mut evaluator = config.token_extractor.evaluator();
    evaluator.bind_attributes(&HandlerAttributesBinding::partial(headers_state.handler()));

    let token: String = evaluator
        .eval()
        .and_then(TryFromValue::try_from_value)
        .map_err(|_| FilterError::NoToken)?;

    // Sends the token to the introspection endpoint
    let response = introspect_token(token.as_str(), config, client).await?;

    // Obtains the current time
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| FilterError::Unexpected)?
        .as_secs();

    // Validates if the token is active
    if !response.active {
        return Err(FilterError::InactiveToken);
    }

    // Validates if the token has expired
    if response.exp.map(|exp| now > exp).unwrap_or_default() {
        return Err(FilterError::ExpiredToken);
    }

    // Validates if the token has started its validity period
    if response.nbf.map(|nbf| now < nbf).unwrap_or_default() {
        return Err(FilterError::NotYetActive);
    }

    // Validates if the aud matches the required aud
    if response.aud != config.required_aud {
        return Err(FilterError::WrongAud);
    }

    // Validates if the iss matches the required iss
    if response.iss != config.required_iss {
        return Err(FilterError::WrongIss);
    }

    // Validates if the required scopes are present in the token
    if let Some(required_scopes_str) = &config.required_scope {
        let required_scopes: Vec<&str> = required_scopes_str.split_whitespace().collect();
        logger::debug!("Required scopes: {:?}", required_scopes);
        let token_scopes: Vec<&str> = response.scope.split_whitespace().collect();
        logger::debug!("Token scopes: {:?}", token_scopes);

        if !required_scopes.iter().all(|&required_scope| token_scopes.contains(&required_scope)) {
        return Err(FilterError::MissingScope);
        }
    }
    
    // Validation succeeded!
    Ok(response)
}

/// Generates a standard early response that indicates the token validation failed
fn unauthorized_response(error_description: &str) -> Flow<()> {
    let body = serde_json::json!({
        "error": "unauthorized",
        "error_description": error_description
    })
    .to_string();

    Flow::Break(
        Response::new(401)
            .with_headers(vec![(
                "WWW-Authenticate".to_string(),
                "Bearer realm=\"oauth2\"".to_string(),
            )])
            .with_body(body),
    )
}

/// Generates a standard early response that indicates that there was an unexpected error
fn server_error_response() -> Flow<()> {
    Flow::Break(Response::new(500))
}

/// Defines a filter function that works as a wrapper for the real filter function that enables simplified error handling
async fn request_filter(state: RequestState, client: HttpClient, config: &Config) -> Flow<()> {
    let state = state.into_headers_state().await;

    match do_filter(&state, config, client).await {
       
        Ok(response) => {
            if config.use_application_jwt_header {
                logger::debug!("Using application/jwt header");
            }
            else {
                logger::debug!("Using phantom_token claim");
            }

            state.handler().remove_header("Authorization");
            state.handler().add_header("Authorization", response.phantom_token.as_str());
            Flow::Continue(())
        },

        Err(err) => match err {
            FilterError::Unexpected => {
                logger::warn!("Unexpected error occurred while processing the request.");
                server_error_response()
            }
            FilterError::NoToken => {
                logger::debug!("No authorization token was provided");
                unauthorized_response("No authorization token was provided")
            }
            FilterError::InactiveToken => {
                logger::debug!("Token is marked as inactive by the introspection endpoint.");
                unauthorized_response("Inactive token")
            }
            FilterError::ExpiredToken => {
                logger::debug!("Expiration time on the token has been exceeded.");
                unauthorized_response("Token has expired")
            }
            FilterError::NotYetActive => {
                logger::debug!(
                    "Token is not yet valid, since time set in the nbf claim has not been reached."
                );
                unauthorized_response("Token is not yet valid")
            }
            FilterError::ClientError(err) => {
                logger::warn!(
                    "Error sending the request to the introspection endpoint. {:?}.",
                    err
                );
                server_error_response()
            }
            FilterError::NonParsableIntrospectionBody(err) => {
                logger::warn!(
                    "Error parsing the response from the introspection endpoint. {}.",
                    err
                );
                server_error_response()
            }
            FilterError::MissingScope => {
                logger::debug!("Required scope(s) missing in token.");
                unauthorized_response("Missing required scope") // Return 401 Unauthorized when scope is missing
            }
            FilterError::InvalidToken => {
                logger::debug!("Invalid token");
                unauthorized_response("Invalid token") // Return 401 for invalid token
            }
            FilterError::ParseJwt(_) => {
                logger::debug!("Error parsing JWT");
                server_error_response() // Return 500 for invalid token
            }
            FilterError::WrongAud => {
                logger::debug!("Invalid audience");
                unauthorized_response("Invalid audience") // Return 401 for invalid audience
            }
            FilterError::WrongIss => {
                logger::debug!("Invalid issuer");
                unauthorized_response("Invalid issuer") // Return 401 for invalid issuer
            }
        },
    }
}

#[entrypoint]
async fn configure(launcher: Launcher, Configuration(bytes): Configuration) -> Result<()> {
    let config: Config = serde_json::from_slice(&bytes).map_err(|err| {
        anyhow!(
            "Failed to parse configuration '{}'. Cause: {}",
            String::from_utf8_lossy(&bytes),
            err
        )
    })?;

    launcher
        .launch(on_request(|request, client| {
            request_filter(request, client, &config)
        }))
        .await?;

    Ok(())
}