use std::fmt;
use std::error::Error;

#[derive(Debug)]
pub enum AppError {
    IoError(String),
    NetworkError(String),
    NoBatchFiles,
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::IoError(msg) => write!(f, "Ошибка ввода/вывода: {}", msg),
            AppError::NetworkError(msg) => write!(f, "Ошибка сети: {}", msg),
            AppError::NoBatchFiles => write!(f, "Конфиги не найдены в директории"),
        }
    }
}

impl Error for AppError {}

pub type AppResult<T> = Result<T, AppError>;