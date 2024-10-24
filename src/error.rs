use std::fmt;
use std::error::Error;
use std::io;
use native_tls; // Import the native_tls crate

#[derive(Debug)]
pub enum AppError {
    IoError(String),
    NetworkError(String),
    NoBatchFiles,
    InputError(String),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::IoError(msg) => write!(f, "Ошибка ввода/вывода: {}", msg),
            AppError::NetworkError(msg) => write!(f, "Ошибка сети: {}", msg),
            AppError::NoBatchFiles => write!(f, "Конфиги не найдены в директории"),
            AppError::InputError(msg) => write!(f, "Ошибка ввода: {}", msg),
        }
    }
}

impl Error for AppError {}

// Implement conversion from io::Error to AppError
impl From<io::Error> for AppError {
    fn from(error: io::Error) -> Self {
        AppError::IoError(error.to_string())
    }
}

// Implement conversion from native_tls::Error to AppError
impl From<native_tls::Error> for AppError {
    fn from(error: native_tls::Error) -> Self {
        AppError::NetworkError(error.to_string())
    }
}

pub type AppResult<T> = Result<T, AppError>;
