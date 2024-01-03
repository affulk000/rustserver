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
type Users = Arc<HashMap<String, User>>;
type Result<T, Err = error::Error> = std::result::Result<T, Err>;

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
    let users = init_users();

    let login_route = warp::path!("login")
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

    let routes = login_route
        .or(user_route)
        .or(admin_route)
        .recover(error::handle_rejection);

    warp::serve(routes).run(([127, 0, 0, 1], 3030)).await;
}

fn with_users(users: Users) -> impl Filter<Extract = (Users,), Error = Infallible> + Clone {
    warp::any().map(move || users.clone())
}


pub async fn login_handler(
    users: Users,
    request: LoginRequest,
) -> WebResult<impl Reply, Rejection> {
    match users.get(&request.email) {
        Some(user) => {

            // create a JWT token with the encoding key and the user's role
            let token = auth::create_jwt(&user.uid, &Role::User).expect("Failed to create JWT");

            // Return the token as a JSON response (e.g. {"token": "your_token"}
            Ok(reply::json(&LoginResponse { token }))
        }
        _ => Err(reject::custom(InvalidCredentials)),
    }
}

pub async fn user_handler(uid: String) -> WebResult<impl Reply, Rejection> {
    Ok(reply::json(&uid))
}
pub async fn admin_handler(uid: String) -> WebResult<impl Reply, Rejection> {
    Ok(reply::json(&uid))
}

fn init_users() -> Users {
    let mut users = HashMap::new();
    let user = User {
        uid: String::from("1"),
        email: "user@example.com".to_string(),
        password: "XXXXXXXX".to_string(),
        role: "user".to_string(),
    };
    users.insert(user.email.clone(), user);
    let admin = User {
        uid: String::from("2"),
        email: "admin@example.com".to_string(),
        password: "XXXXXXXX".to_string(),
        role: "admin".to_string(),
    };
    users.insert(admin.email.clone(), admin);
    Arc::new(users)
}
