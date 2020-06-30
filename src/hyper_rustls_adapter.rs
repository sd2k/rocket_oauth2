use std::convert::TryInto;

use hyper::{
    header::{ACCEPT, CONTENT_TYPE},
    Body, Client, Request, Response,
};
use hyper_rustls::HttpsConnector;
use rocket::http::ext::IntoOwned;
use rocket::http::uri::Absolute;
use url::form_urlencoded::Serializer as UrlSerializer;
use url::Url;

use super::{Adapter, Error, ErrorKind, OAuthConfig, TokenRequest, TokenResponse};

/// The default `Adapter` implementation. Uses `hyper` and `rustls` to perform the token exchange.
#[derive(Clone, Debug)]
pub struct HyperRustlsAdapter;

#[rocket::async_trait]
impl Adapter for HyperRustlsAdapter {
    fn authorization_uri(
        &self,
        config: &OAuthConfig,
        state: &str,
        scopes: &[&str],
    ) -> Result<Absolute<'static>, Error> {
        let auth_uri = config.provider().auth_uri();

        let mut url = Url::parse(&auth_uri)
            .map_err(|e| Error::new_from(ErrorKind::InvalidUri(auth_uri.to_string()), e))?;

        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", config.client_id())
            .append_pair("state", state);

        if let Some(redirect_uri) = config.redirect_uri() {
            url.query_pairs_mut()
                .append_pair("redirect_uri", redirect_uri);
        }

        if !scopes.is_empty() {
            url.query_pairs_mut()
                .append_pair("scope", &scopes.join(" "));
        }

        Ok(Absolute::parse(url.as_ref())
            .map_err(|_| Error::new(ErrorKind::InvalidUri(url.to_string())))?
            .into_owned())
    }

    async fn exchange_code(
        &self,
        config: &OAuthConfig,
        token: TokenRequest,
    ) -> Result<TokenResponse<()>, Error> {
        let https = HttpsConnector::new();
        let client: Client<_, Body> = Client::builder().build(https);

        let req_str = {
            let mut ser = UrlSerializer::new(String::new());
            match token {
                TokenRequest::AuthorizationCode(code) => {
                    ser.append_pair("grant_type", "authorization_code");
                    ser.append_pair("code", &code);
                    if let Some(redirect_uri) = config.redirect_uri() {
                        ser.append_pair("redirect_uri", redirect_uri);
                    }
                }
                TokenRequest::RefreshToken(token) => {
                    ser.append_pair("grant_type", "refresh_token");
                    ser.append_pair("refresh_token", &token);
                }
            }
            ser.append_pair("client_id", config.client_id());
            ser.append_pair("client_secret", config.client_secret());

            ser.finish()
        };

        let url = config.provider().token_uri();
        let request = Request::post(url.as_ref())
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(req_str.into())
            .map_err(|e| Error::new_from(ErrorKind::InvalidUri(url.to_string()), e))?;

        let response: Response<Body> = client
            .request(request)
            .await
            .map_err(|e| Error::new_from(ErrorKind::ExchangeFailure, e))?;

        if !response.status().is_success() {
            return Err(Error::new(ErrorKind::ExchangeError(
                response.status().into(),
            )));
        }

        let body = hyper::body::to_bytes(response)
            .await
            .map_err(|e| Error::new_from(ErrorKind::ExchangeFailure, e))?;

        let data: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|e| Error::new_from(ErrorKind::ExchangeFailure, e))?;
        Ok(data.try_into()?)
    }
}
