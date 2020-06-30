#![feature(decl_macro, proc_macro_hygiene)]

use anyhow::{Context, Error};
use hyper::{
    header::{ACCEPT, AUTHORIZATION, USER_AGENT},
    Body, Client,
};
use hyper_rustls::HttpsConnector;
use rocket::http::{Cookie, Cookies, SameSite};
use rocket::request::{self, FromRequest, Request};
use rocket::response::{Debug, Redirect};
use rocket::{get, routes, Outcome};
use rocket_oauth2::{OAuth2, TokenResponse};
use serde_json::{self, Value};

struct User {
    pub username: String,
}

#[rocket::async_trait]
impl<'a, 'r> FromRequest<'a, 'r> for User {
    type Error = ();

    async fn from_request(request: &'a Request<'r>) -> request::Outcome<User, ()> {
        let mut cookies = request
            .guard::<Cookies<'_>>()
            .await
            .expect("request cookies");
        if let Some(cookie) = cookies.get_private("username") {
            return Outcome::Success(User {
                username: cookie.value().to_string(),
            });
        }

        Outcome::Forward(())
    }
}

/// User information to be retrieved from the GitHub API.
#[derive(serde::Deserialize)]
struct GitHubUserInfo {
    #[serde(default)]
    name: String,
}

// NB: Here we are using the same struct as a type parameter to OAuth2 and
// TokenResponse as we use for the user's GitHub login details. For
// `TokenResponse` and `OAuth2` the actual type does not matter; only that they
// are matched up.
#[get("/login/github")]
fn github_login(oauth2: OAuth2<GitHubUserInfo>, mut cookies: Cookies<'_>) -> Redirect {
    oauth2.get_redirect(&mut cookies, &["user:read"]).unwrap()
}

#[get("/auth/github")]
async fn github_callback(
    token: TokenResponse<GitHubUserInfo>,
    mut cookies: Cookies<'_>,
) -> Result<Redirect, Debug<Error>> {
    let https = HttpsConnector::new();
    let client: Client<_, Body> = Client::builder().build(https);

    // Use the token to retrieve the user's GitHub account information.
    let mime = "application/vnd.github.v3+json";
    let request = hyper::Request::get("https://api.github.com/user")
        .header(AUTHORIZATION, format!("token {}", token.access_token()))
        .header(ACCEPT, mime)
        .header(USER_AGENT, "rocket_oauth2 demo application")
        .body(Body::empty())
        .context("failed to build request")?;

    let response = client
        .request(request)
        .await
        .context("failed to send request to API")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "got non-success status {}",
            response.status()
        ))?;
    }

    let body = hyper::body::to_bytes(response)
        .await
        .context("failed to read response")?;

    let user_info: GitHubUserInfo =
        serde_json::from_slice(&body).context("failed to deserialize response")?;

    // Set a private cookie with the user's name, and redirect to the home page.
    cookies.add_private(
        Cookie::build("username", user_info.name)
            .same_site(SameSite::Lax)
            .finish(),
    );
    Ok(Redirect::to("/"))
}

/// User information to be retrieved from the Google People API.
#[derive(serde::Deserialize)]
struct GoogleUserInfo {
    names: Vec<Value>,
}

#[get("/login/google")]
fn google_login(oauth2: OAuth2<GoogleUserInfo>, mut cookies: Cookies<'_>) -> Redirect {
    oauth2.get_redirect(&mut cookies, &["profile"]).unwrap()
}

#[get("/auth/google")]
async fn google_callback(
    token: TokenResponse<GoogleUserInfo>,
    mut cookies: Cookies<'_>,
) -> Result<Redirect, Debug<Error>> {
    let https = HttpsConnector::new();
    let client: Client<_, Body> = Client::builder().build(https);

    // Use the token to retrieve the user's Google account information.
    let request =
        hyper::Request::get("https://people.googleapis.com/v1/people/me?personFields=names")
            .header(AUTHORIZATION, format!("Bearer {}", token.access_token()))
            .body(Body::empty())
            .context("failed to build request")?;

    let response = client
        .request(request)
        .await
        .context("failed to send request to API")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "got non-success status {}",
            response.status()
        ))?;
    }

    let body = hyper::body::to_bytes(response)
        .await
        .context("failed to read response")?;

    let user_info: GoogleUserInfo =
        serde_json::from_slice(&body).context("failed to deserialize response")?;

    let real_name = user_info
        .names
        .first()
        .and_then(|n| n.get("displayName"))
        .and_then(|s| s.as_str())
        .unwrap_or("");

    // Set a private cookie with the user's name, and redirect to the home page.
    cookies.add_private(
        Cookie::build("username", real_name.to_string())
            .same_site(SameSite::Lax)
            .finish(),
    );
    Ok(Redirect::to("/"))
}

/// User information to be retrieved from the Microsoft API.
#[derive(serde::Deserialize)]
struct MicrosoftUserInfo {
    #[serde(default, rename = "displayName")]
    display_name: String,
}

#[get("/login/microsoft")]
fn microsoft_login(oauth2: OAuth2<MicrosoftUserInfo>, mut cookies: Cookies<'_>) -> Redirect {
    oauth2.get_redirect(&mut cookies, &["user.read"]).unwrap()
}

#[get("/auth/microsoft")]
async fn microsoft_callback(
    token: TokenResponse<MicrosoftUserInfo>,
    mut cookies: Cookies<'_>,
) -> Result<Redirect, Debug<Error>> {
    let https = HttpsConnector::new();
    let client: Client<_, Body> = Client::builder().build(https);

    // Use the token to retrieve the user's Microsoft account information.
    let request = hyper::Request::get("https://graph.microsoft.com/v1.0/me")
        .header(AUTHORIZATION, format!("Bearer {}", token.access_token()))
        .body(Body::empty())
        .context("failed to build request")?;

    let response = client
        .request(request)
        .await
        .context("failed to send request to API")?;

    if !response.status().is_success() {
        return Err(anyhow::anyhow!(
            "got non-success status {}",
            response.status()
        ))?;
    }

    let body = hyper::body::to_bytes(response)
        .await
        .context("failed to read response")?;

    let user_info: MicrosoftUserInfo =
        serde_json::from_slice(&body).context("failed to deserialize response")?;

    // Set a private cookie with the user's name, and redirect to the home page.
    cookies.add_private(
        Cookie::build("username", user_info.display_name.to_string())
            .same_site(SameSite::Lax)
            .finish(),
    );
    Ok(Redirect::to("/"))
}

#[get("/")]
fn index(user: User) -> String {
    format!("Hi, {}!", user.username)
}

#[get("/", rank = 2)]
fn index_anonymous() -> &'static str {
    "Please login (/login/github or /login/google or /login/microsoft)"
}

#[get("/logout")]
fn logout(mut cookies: Cookies<'_>) -> Redirect {
    cookies.remove(Cookie::named("username"));
    Redirect::to("/")
}

#[rocket::main]
async fn main() {
    rocket::ignite()
        .mount(
            "/",
            routes![
                index,
                index_anonymous,
                logout,
                github_callback,
                google_callback,
                microsoft_callback,
                github_login,
                google_login,
                microsoft_login,
            ],
        )
        .attach(OAuth2::<GitHubUserInfo>::fairing("github"))
        .attach(OAuth2::<GoogleUserInfo>::fairing("google"))
        .attach(OAuth2::<MicrosoftUserInfo>::fairing("microsoft"))
        .launch()
        .await
        .expect("Rocket error")
}
