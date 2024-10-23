use std::path::{Path, PathBuf};
use std::time::Duration;
use std::fs;
use crate::error::{AppError, AppResult};

pub struct Config {
    pub batch_dir: PathBuf,
    pub target_domain: String,
    pub process_name: String,
    pub process_wait_timeout: Duration,
    pub connection_timeout: Duration,
}

impl Config {
    pub fn get_batch_files(&self) -> AppResult<Vec<PathBuf>> {
        let entries = fs::read_dir(&self.batch_dir)
            .map_err(|e| AppError::IoError(format!("Failed to read directory: {}", e)))?;

        let batch_files: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.path().is_file() &&
                    entry.path().extension().map_or(false, |ext| ext == "bat")
            })
            .map(|entry| entry.path())
            .collect();

        if batch_files.is_empty() {
            return Err(AppError::NoBatchFiles);
        }

        Ok(batch_files)
    }
}