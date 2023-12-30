use auth::{with_auth, Role};
use error::Error::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use warp::{reject, reply, Filter, Rejection, Reply, };

mod auth;
mod error;

type WebResult<T, E = Rejection> = std::result::Result<T, E>;
type UserMap = Arc<HashMap<String, User>>;
type Result<T, Err = Error> = std::result::Result<T, Err>;

#[derive(Clone)]
pub struct User {
    pub uid: String,
    pub email: String,
    pub password: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct LoginResponse {
    pub token: String,
}

#[tokio::main]
async fn main() {
    let users = Arc::new(init_users());

    let login = warp::path!("login")
        .and(warp::post())
        .and(with_users(users.clone()))
        .and(warp::body::json())
        .and_then(login_handler);

    let user_route = warp::path!("user")
        .and(with_auth(Role::User))
        .and_then(user_handler);

    let admin_route = warp::path!("admin")
        .and(with_auth(Role::Admin))
        .and_then(admin_handler);

    let routes = login
        .or(user_route)
        .or(admin_route)
        .recover(error::handle_rejection);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

fn with_users(users: UserMap) -> impl Filter<Extract = (UserMap,), Error = Infallible> + Clone {
    warp::any().map(move || users.clone())
}

pub async fn login_handler(
    users: UserMap,
    request: LoginRequest,
) -> WebResult<impl Reply, Rejection> {
    match users.iter().find(|(_uid,user)| user.email == request.email && user.password == request.password) {
        Some((_uid, user)) => Ok(reply::json(&LoginResponse {
            token: user.uid.clone(),
        })),
        None => Err(reject::custom(InvalidCredentials)),
    }
}

pub async fn user_handler(uid: String) -> WebResult<impl Reply, Rejection> {
    Ok(reply::json(&uid))
}
pub async fn admin_handler(uid: String) -> WebResult<impl Reply, Rejection> {
    Ok(reply::json(&uid))
}

fn init_users() -> UserMap {
    let mut users = HashMap::new();
    let user = User {
        uid: "1".to_string(),
        email: "user@example.com".to_string(),
        password: "XXXXXXXX".to_string(),
        role: "user".to_string(),
    };
    users.insert(user.email.clone(), user);
    let admin = User {
        uid: "2".to_string(),
        email: "admin@example.com".to_string(),
        password: "XXXXXXXX".to_string(),
        role: "admin".to_string(),
    };
    users.insert(admin.email.clone(), admin);
    Arc::new(users)
}
