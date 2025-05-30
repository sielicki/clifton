// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use oauth2::{
    basic::BasicClient, AuthType, AuthUrl, ClientId, DeviceAuthorizationUrl, Scope,
    StandardDeviceAuthorizationResponse, TokenUrl,
};
use oauth2::{AccessToken, TokenResponse as _};
use qrcode::{render::unicode, QrCode};
use url::Url;

/// Given an OAuth `client_id` and URL, authenticate with the device code workflow
pub fn get_access_token(
    client_id: &String,
    issuer_url: &Url,
    open_webpage: bool,
    show_qr: bool,
) -> Result<AccessToken> {
    // let http_client = reqwest::blocking::Client::new();
    let http_client = oauth2::reqwest::blocking::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Could not build HTTP client for authorisation.")?;

    let client_id = ClientId::new(client_id.to_string());

    // TODO get these from https://{provider}/realms/{realm}/.well-known/openid-configuration
    let auth_url =
        AuthUrl::from_url(format!("{issuer_url}/protocol/openid-connect/auth/device").parse()?);
    let token_url =
        TokenUrl::from_url(format!("{issuer_url}/protocol/openid-connect/token").parse()?);
    let device_auth_url = DeviceAuthorizationUrl::from_url(
        format!("{issuer_url}/protocol/openid-connect/auth/device").parse()?,
    );
    // Set up the config for the OIDC process.
    let device_client = BasicClient::new(client_id)
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_device_authorization_url(device_auth_url)
        .set_auth_type(AuthType::RequestBody);

    // Request the set of codes from the Device Authorization endpoint.
    let details: StandardDeviceAuthorizationResponse = device_client
        .exchange_device_code()
        .add_scope(Scope::new("openid".to_string()))
        .request(&http_client)
        .context("Failed to request codes from device auth endpoint.")?;

    // Display the URL and user-code.
    let verification_uri_complete = details
        .verification_uri_complete()
        .context("Did not receive complete verification URI from server.")?
        .secret();
    if open_webpage {
        if let Err(e) = webbrowser::open(verification_uri_complete) {
            eprintln!("Could not launch web browser: {e:#}");
        }
    }
    println!("Open this URL in your browser:\n{verification_uri_complete}");
    if show_qr {
        let qr_code_url = Url::parse_with_params(verification_uri_complete, &[("qr", "1")])?;
        let qr = QrCode::new(qr_code_url.as_str())?
            .render::<unicode::Dense1x2>()
            .light_color(unicode::Dense1x2::Light)
            .dark_color(unicode::Dense1x2::Dark)
            .build();
        println!("Or scan this QR code:\n{qr}");
    }

    // Now poll for the token
    let token = device_client
        .exchange_device_access_token(&details)
        .request(&http_client, std::thread::sleep, None)
        .context("Could not get token from identity provider.")?;

    Ok(token.access_token().clone())
}
