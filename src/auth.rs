use crate::{error::Error, Result, WebResult};
use chrono::prelude::*;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use std::fmt;
use warp::{
    filters::header::headers_cloned,
    http::header::{HeaderMap, HeaderValue, AUTHORIZATION},
    reject, Filter, Rejection,
};

const BEARER_PREFIX: &str = "Bearer ";
const JWT_SECRET: &[u8] = b"secret";

#[derive(Clone, PartialEq)]
pub enum Role {
    User,
    Admin,
}
impl Role {
    pub fn from_str(role: &str) -> Option<Role> {
        match role {
            "User" => Some(Role::User),
            "Admin" => Some(Role::Admin),
            _ => None,
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Role::User => write!(f, "User"),
            Role::Admin => write!(f, "Admin"),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct Claims {
    sub: String,
    role: String,
    exp: usize,
}

pub fn with_auth(role: Role) -> impl Filter<Extract = (String,), Error = Rejection> + Clone {
    headers_cloned()
        .map(move |headers: HeaderMap<HeaderValue>| (role.clone(), headers))
        .and_then(authorize)
}

pub fn create_jwt(uid: &str, role: &Role) -> Result<String> {
    const TOKEN_LIFETIME_SECONDS: i64 = 60;
    let expiration = Utc::now()
        .checked_add_signed(chrono::Duration::seconds(TOKEN_LIFETIME_SECONDS))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: uid.to_owned(),
        role: role.to_string(),
        exp: expiration as usize,
    };

    let header = Header::new(Algorithm::HS256);
    encode(&header, &claims, &EncodingKey::from_secret(JWT_SECRET))
        .map_err(|_| Error::JWTTokenCreationError)
}

async fn authorize((role, headers): (Role, HeaderMap<HeaderValue>)) -> WebResult<String> {
    match jwt_from_header(&headers) {
        Ok(jwt) => {
            let token_data = decode::<Claims>(
                &jwt,
                &DecodingKey::from_secret(JWT_SECRET),
                &Validation::new(Algorithm::HS256),
            )
            .map_err(|_| reject::custom(Error::JWTTokenError))?;
            if role == Role::Admin && Role::from_str(&token_data.claims.role) != Some(Role::Admin) {
                return Err(reject::custom(Error::NoPermissionError));
            }

            Ok(token_data.claims.sub)
        }
        Err(_) => Err(reject::custom(Error::NoPermissionError)),
    }
}

fn jwt_from_header(headers: &HeaderMap<HeaderValue>) -> Result<String, Rejection> {
    let header = match headers.get(AUTHORIZATION) {
        Some(v) => v,
        None => return Err(reject::custom(Error::NoAuthHeaderError)),
    };
    let auth_header = match std::str::from_utf8(header.as_bytes()) {
        Ok(v) => v,
        Err(_) => return Err(reject::custom(Error::NoAuthHeaderError)),
    };
    if !auth_header.starts_with(BEARER_PREFIX) {
        return Err(reject::custom(Error::InvalidAuthHeaderError));
    }
    Ok(auth_header.trim_start_matches(BEARER_PREFIX).to_owned())
}
