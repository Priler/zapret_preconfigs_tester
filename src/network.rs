use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use crate::error::{AppError, AppResult};

pub struct NetworkChecker;

impl NetworkChecker {
    pub fn new() -> Self {
        Self
    }

    pub fn test_connection(&self, target: &str, timeout: Duration) -> AppResult<bool> {
        let addrs = target.to_socket_addrs()
            .map_err(|e| AppError::NetworkError(format!("Failed to resolve address: {}", e)))?;

        for addr in addrs {
            if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                return Ok(true);
            }
        }

        Ok(false)
    }
}