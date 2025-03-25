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

    #[error(
        "You didn't provide an API key. You need to provide your API key in an Authorization header using Bearer auth (i.e. Authorization: Bearer YOUR_KEY), or as the password field (with blank username) if you're accessing the API from your browser and are prompted for a username and password. You can obtain an API key from https://platform.openai.com/account/api-keys."
    )]
    InvalidApiKey,
}
