// network.rs
use std::net::{ToSocketAddrs, TcpStream};
use std::time::Duration;
use std::io::{self, Read, Write};
use crate::error::AppResult;
use ureq::Error as UreqError;

pub struct NetworkChecker {
    timeout: Duration,
}

impl NetworkChecker {
    pub fn new(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub fn test_connection(&self, target: &str) -> AppResult<bool> {
        let domain = target.split(':').next().unwrap_or(target);
        let result = self.try_connect(domain)?;
        Ok(result == ConnectionResult::Success)
    }

    pub fn check_dpi_fingerprint(&self, domain: &str) -> AppResult<DPITestResult> {
        println!("Проверка соединения с {}...", domain);

        match self.try_connect(domain)? {
            ConnectionResult::Success => Ok(DPITestResult::NoDPI),
            ConnectionResult::ConnectionReset => Ok(DPITestResult::DPIDetected),
            ConnectionResult::NoConnection => Ok(DPITestResult::NoConnection),
            ConnectionResult::Timeout => Ok(DPITestResult::DPIDetected),
        }
    }

    fn try_connect(&self, domain: &str) -> AppResult<ConnectionResult> {
        let addr = format!("{}:443", domain);
        println!("DEBUG: Trying to connect to {}...", addr);

        let sock_addr = match addr.to_socket_addrs() {
            Ok(mut addrs) => match addrs.next() {
                Some(addr) => addr,
                None => {
                    println!("DEBUG: DNS resolution succeeded but no addresses returned");
                    return Ok(ConnectionResult::NoConnection);
                }
            },
            Err(e) => {
                println!("DEBUG: DNS resolution failed: {}", e);
                return Ok(ConnectionResult::NoConnection);
            }
        };

        let mut stream = match TcpStream::connect_timeout(&sock_addr, self.timeout) {
            Ok(stream) => stream,
            Err(e) => {
                println!("DEBUG: Connection error: {}", e);
                if e.kind() == io::ErrorKind::TimedOut {
                    return Ok(ConnectionResult::Timeout);
                } else {
                    return Ok(ConnectionResult::ConnectionReset);
                }
            }
        };

        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;

        // Send an HTTPS GET request
        let http_request = format!(
            "GET / HTTP/1.1\r\n\
     Host: {}\r\n\
     Connection: close\r\n\r\n",
            domain
        );

        match stream.write_all(http_request.as_bytes()) {
            Ok(_) => {
                println!("DEBUG: HTTPS request sent successfully");

                // Read response
                let mut buf = [0; 1024];
                let mut response = Vec::new();
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break, // End of response
                        Ok(n) => response.extend_from_slice(&buf[..n]),
                        Err(e) => {
                            println!("DEBUG: Error reading HTTPS response: {}\n", e);
                            if e.kind() == io::ErrorKind::TimedOut {
                                return Ok(ConnectionResult::Timeout);
                            } else {
                                return Ok(ConnectionResult::ConnectionReset);
                            }
                        }
                    }
                }

                // println!("DEBUG: HTTPS response received: {:?}", response);

                Ok(ConnectionResult::Success)
            },
            Err(e) => {
                println!("DEBUG: HTTPS request failed: {}\n", e);
                if e.kind() == io::ErrorKind::TimedOut {
                    Ok(ConnectionResult::Timeout)
                } else {
                    Ok(ConnectionResult::ConnectionReset)
                }
            },
        }
    }
}

#[derive(Debug, PartialEq)]
enum ConnectionResult {
    Success,
    ConnectionReset,
    Timeout,
    NoConnection,
}

#[derive(Debug, PartialEq)]
pub enum DPITestResult {
    NoDPI,
    DPIDetected,
    NoConnection,
    Unclear,
}

impl DPITestResult {
    pub fn to_russian_string(&self) -> String {
        match self {
            DPITestResult::NoDPI => "DPI не обнаружен, сайт доступен напрямую".to_string(),
            DPITestResult::DPIDetected => "Обнаружена DPI блокировка".to_string().to_uppercase(),
            DPITestResult::NoConnection => "Нет соединения с сайтом".to_string(),
            DPITestResult::Unclear => "Результат проверки неясен".to_string(),
        }
    }
}