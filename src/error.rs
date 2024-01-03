use serde::Serialize;

use std::convert::Infallible;
use thiserror::Error;
use warp::{http::StatusCode, reject::Rejection, Reply};

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid jwt token creation error")]
    JWTTokenCreationError,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("JWT token imvalid")]
    JWTTokenError,
    #[error("No permission auth")]
    NoPermissionError,
    #[error("wrong authentication")]
    NoAuthHeaderError,
    #[error("invalid authenticaton header")]
    InvalidAuthHeaderError,
}

impl warp::reject::Reject for Error {}

#[derive(Serialize, Debug)]
struct ErrorResponse {
    message: String,
    status: String,

}



pub async fn handle_rejection(err: Rejection) -> std::result::Result<impl Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (StatusCode::NOT_FOUND, "Not Found".to_string())
    } else if let Some(e) = err.find::<Error>() {
        match e  {
            Error::JWTTokenCreationError => (StatusCode::INTERNAL_SERVER_ERROR, "JWTTokenCreationError".to_string()),
            Error::InvalidCredentials => (StatusCode::UNAUTHORIZED, "InvalidCredentials".to_string()),
            Error::JWTTokenError => (StatusCode::UNAUTHORIZED, "JWTTokenError".to_string()),
            Error::NoPermissionError => (StatusCode::UNAUTHORIZED, "NoPermissionError".to_string()),
            Error::NoAuthHeaderError => (StatusCode::UNAUTHORIZED, "NoAuthHeaderError".to_string()),
            Error::InvalidAuthHeaderError => (StatusCode::UNAUTHORIZED, "InvalidAuthHeaderError".to_string()),
        }
    } else if let Some(e) = err.find::<warp::reject::UnsupportedMediaType>() {
        (StatusCode::UNSUPPORTED_MEDIA_TYPE, e.to_string())
    }
    else {
        eprintln!("unhandled error: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error".to_string(),
        )
    };
    let json = warp::reply::json(&ErrorResponse {
        message,
        status: code.as_str().to_string(),
        // status: code.as_str().to_string(),
        // message: err.to_string(),
    });
    Ok(warp::reply::with_status(json, code))
}
