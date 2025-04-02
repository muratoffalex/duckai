#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    IOError(#[from] std::io::Error),

    #[error(transparent)]
    SerdeYamlError(#[from] serde_yaml::Error),

    #[error(transparent)]
    RequestError(#[from] reqwest::Error),

    #[error(transparent)]
    LogParseError(#[from] tracing_subscriber::filter::ParseError),

    #[error(transparent)]
    LogSetGlobalDefaultError(#[from] tracing::subscriber::SetGlobalDefaultError),

    #[error(transparent)]
    JsonExtractorRejection(#[from] axum::extract::rejection::JsonRejection),

    #[error("Missing or invalid 'x-vqd-4' header")]
    MissingHeader,

    #[error("{0}")]
    BadRequest(String),

    #[error("{0}")]
    HashError(&'static str),

    #[error("invalid api key")]
    InvalidApiKey,
}
