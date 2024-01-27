use skf_api::native::error::get_message;
use std::fmt::{Debug, Display, Formatter};
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    InvalidArgument(#[from] InvalidArgumentError),
    #[error(transparent)]
    LibLoading(#[from] libloading::Error),
    #[error(transparent)]
    Skf(#[from] SkfErr),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(thiserror::Error, Debug)]
pub struct InvalidArgumentError {
    msg: String,
    #[source]
    source: anyhow::Error,
}

impl InvalidArgumentError {
    pub fn new(msg: impl AsRef<str>, source: anyhow::Error) -> Self {
        Self {
            msg: msg.as_ref().to_string(),
            source,
        }
    }
}

impl Display for InvalidArgumentError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}

#[derive(Clone)]
pub struct SkfErr {
    pub code: u32,
    pub message: String,
}

impl SkfErr {
    pub fn new(code: u32, message: impl AsRef<str>) -> Self {
        Self {
            code,
            message: message.as_ref().to_string(),
        }
    }

    pub fn with_default_msg(code: u32) -> Self {
        let message = get_message(code).unwrap_or("Unknown error");
        Self::new(code, message)
    }
}
impl std::error::Error for SkfErr {}

impl Display for SkfErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:#010x}] - {}", self.code, &self.message)
    }
}

impl Debug for SkfErr {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:#010x}({}) ] - {}",
            self.code, self.code, &self.message
        )
    }
}
