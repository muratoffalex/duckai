use crate::client::{HttpConfig, build_client};
use crate::{Result, config::Config, error::Error};
use axum::{
    Json, Router,
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
};
use axum_extra::TypedHeader;
use axum_extra::headers::{Authorization, authorization::Bearer};
use axum_server::tls_rustls::RustlsConfig;
use hyper_util::rt::TokioTimer;
use reqwest::Client;
use serde::Serialize;
use std::sync::Mutex;
use std::{
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};
use tracing::Level;
use tracing_subscriber::{EnvFilter, FmtSubscriber};
use typed_builder::TypedBuilder;

#[derive(Clone, TypedBuilder)]
pub struct AppState {
    pub client: Client,
    api_key: Arc<Option<String>>,
    pub cache: TokenCache,
}

impl AppState {
    pub fn valid_key(
        &self,
        bearer: Option<TypedHeader<Authorization<Bearer>>>,
    ) -> crate::Result<()> {
        let api_key = bearer.as_deref().map(|b| b.token());
        if let Some(key) = self.api_key.as_deref() {
            if Some(key) != api_key {
                return Err(crate::Error::InvalidApiKey);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
pub struct TokenCache {
    cache: Arc<Mutex<Vec<(String, (String, String), Instant)>>>,
}

impl TokenCache {
    pub fn get_token(&self, req_key: &str) -> Option<(String, String)> {
        let mut cache = self.cache.lock().unwrap();
        cache.retain(|(_, _, ts)| ts.elapsed().as_secs() < 360);
        let item = cache
            .iter_mut()
            .filter(|(key, _, _)| req_key.starts_with(key))
            .max_by_key(|(key, _, _)| key.len());
        if let Some(item) = item {
            item.0 = req_key.to_owned();
            item.2 = Instant::now();
            Some(item.1.clone())
        } else {
            None
        }
    }
    pub fn put_token(&self, req_key: &str, token: (String, String)) {
        let mut cache = self.cache.lock().unwrap();
        for item in cache.iter_mut() {
            if item.0 == req_key {
                item.1 = token;
                item.2 = Instant::now();
                return;
            }
        }
        cache.push((req_key.to_owned(), token, Instant::now()));
    }
}

#[tokio::main]
pub async fn run(path: PathBuf) -> Result<()> {
    // init config
    let config = init_config(path).await?;

    // init logger
    init_logger(config.debug)?;

    // init boot message
    boot_message(&config);

    // init global layer provider
    let global_layer = tower::ServiceBuilder::new().layer(
        CorsLayer::new()
            .allow_credentials(true)
            .allow_headers(AllowHeaders::mirror_request())
            .allow_methods(AllowMethods::mirror_request())
            .allow_origin(AllowOrigin::mirror_request()),
    );

    let http_config = HttpConfig::builder()
        .timeout(config.timeout)
        .connect_timeout(config.connect_timeout)
        .tcp_keepalive(config.tcp_keepalive)
        .build();

    let app_state = AppState::builder()
        .client(build_client(http_config).await)
        .api_key(Arc::new(config.api_key))
        .cache(Default::default())
        .build();

    let router = Router::new()
        .route("/v1/models", get(crate::route::models))
        .route("/v1/chat/completions", post(crate::route::chat_completions))
        .with_state(app_state)
        .layer(global_layer);

    // http server tcp keepalive
    let tcp_keepalive = config.tcp_keepalive.map(Duration::from_secs);

    // Run http server
    match (config.tls_cert.as_ref(), config.tls_key.as_ref()) {
        (Some(cert), Some(key)) => {
            // Load TLS configuration
            let tls_config = RustlsConfig::from_pem_file(cert, key).await?;

            // Use TLS configuration to create a secure server
            let mut server = axum_server::bind_rustls(config.bind, tls_config);
            server
                .http_builder()
                .http1()
                .preserve_header_case(true)
                .http2()
                .timer(TokioTimer::new())
                .keep_alive_interval(tcp_keepalive);

            server.serve(router.into_make_service()).await
        }
        _ => {
            // No TLS configuration, create a non-secure server
            let mut server = axum_server::bind(config.bind);
            server
                .http_builder()
                .http1()
                .preserve_header_case(true)
                .http2()
                .keep_alive_interval(tcp_keepalive);

            server.serve(router.into_make_service()).await
        }
    }
    .map_err(Into::into)
}

fn boot_message(config: &Config) {
    tracing::info!("Bind address: {}", config.bind);
}

/// Initialize the logger with a filter that ignores WARN level logs for netlink_proto
fn init_logger(debug: bool) -> Result<()> {
    let filter = EnvFilter::from_default_env()
        .add_directive(if debug { Level::DEBUG } else { Level::INFO }.into())
        .add_directive("netlink_proto=error".parse()?);
    tracing::subscriber::set_global_default(
        FmtSubscriber::builder().with_env_filter(filter).finish(),
    )?;
    Ok(())
}

/// Init configuration
async fn init_config(path: PathBuf) -> Result<Config> {
    if !path.is_file() {
        Ok(Config::default())
    } else {
        let data = tokio::fs::read(path).await?;
        serde_yaml::from_slice::<Config>(&data).map_err(Into::into)
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> axum::response::Response {
        #[derive(Serialize, TypedBuilder)]
        struct ResponseError {
            message: String,
            #[serde(rename = "type")]
            type_field: &'static str,
            #[builder(default)]
            param: Option<String>,
        }

        match self {
            Error::JsonExtractorRejection(json_rejection) => (
                StatusCode::BAD_REQUEST,
                Json(
                    ResponseError::builder()
                        .message(json_rejection.body_text())
                        .type_field("invalid_request_error")
                        .build(),
                ),
            )
                .into_response(),
            Error::InvalidApiKey => (
                StatusCode::UNAUTHORIZED,
                Json(
                    ResponseError::builder()
                        .message(self.to_string())
                        .type_field("invalid_request_error")
                        .build(),
                ),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(
                    ResponseError::builder()
                        .message(self.to_string())
                        .type_field("server_error")
                        .build(),
                ),
            )
                .into_response(),
        }
    }
}
