use serde::Serialize,
use std::convert::Infallible;
use thiserror::Error;
use warp::{http::StatusCode, reject::Reject, Reply};
pub enum Error {
    #[error("wrong authorization")]
    Unauthorized,
    #[error("invalid credentials")]
    JWTTokenCreationError,
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("invalid credentials")]
    JWTTokenVerificationError,
}

struct ErrorResponse {
    message: String,
    status: String,

}

impl warp::reject::Reject for Error {}

pub async fn handle_rejection(err: Reject) -> std::result::Result<impl Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (StatusCode::NOT_FOUND, "Not Found".to_string())
    } else if let Some(e) = err.find::<Error>() {
        match e  {
            Error::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            Error::JWTTokenCreationError => (StatusCode::INTERNAL_SERVER_ERROR, "JWTTokenCreationError".to_string()),
            Error::JWTTokenVerificationError => (StatusCode::INTERNAL_SERVER_ERROR, "JWTTokenVerificationError".to_string()),
            Error::InvalidCredentials => (StatusCode::UNAUTHORIZED, "InvalidCredentials".to_string()),
        }
    } else if let Some(e) = err.find::<warp::reject::MethodNotAllowed>() {
        (StatusCode::METHOD_NOT_ALLOWED, e.to_string())
    }
    else {
        eprintln!("unhandled error: {:?}", err);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Internal Server Error".to_string(),
        )
    };
}
