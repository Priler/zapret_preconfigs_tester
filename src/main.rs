use std::path::PathBuf;
use std::time::Duration;
use std::io::{self, Write, stdin, stdout};
use std::path::Path;
use std::process::Command;
use std::thread::sleep;

mod config;
mod process;
mod network;
mod error;

use config::Config;
use error::{AppResult, AppError};
use process::ProcessManager;
use network::NetworkChecker;
use crate::network::DPITestResult;

use std::ptr;
use std::mem;
use winapi::um::winnt::{TOKEN_QUERY, TokenElevation, TOKEN_ELEVATION};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::shared::minwindef::{DWORD, BOOL};
use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
use winapi::um::handleapi::CloseHandle;
use std::mem::MaybeUninit;

struct TokenHandle(*mut winapi::ctypes::c_void);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CloseHandle(self.0) };
        }
    }
}

const DEFAULT_PORT: u16 = 443;
const DOMAIN_LIST: &[(&str, &str)] = &[
    ("1", "discord.com"),
    ("2", "youtube.com"),
    ("3", "spotify.com"),
    ("4", "speedtest.net"),
    ("5", "custom")
];

fn is_valid_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 255 {
        return false;
    }

    !domain.contains(':')
        && domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !domain.starts_with('-')
        && !domain.ends_with('-')
}

fn format_domain_with_port(domain: &str) -> String {
    format!("{}:{}", domain.trim(), DEFAULT_PORT)
}

fn get_domain_choice() -> io::Result<String> {
    println!("\nВыберите домен для проверки:");
    for (number, domain) in DOMAIN_LIST {
        if *domain == "custom" {
            println!("{}. Ввести свой домен", number);
        } else {
            println!("{}. {}", number, domain);
        }
    }

    loop {
        print!("\nВведите номер варианта: ");
        stdout().flush()?;

        let mut choice = String::new();
        stdin().read_line(&mut choice)?;
        let choice = choice.trim();

        if let Some((_, domain)) = DOMAIN_LIST.iter().find(|(num, _)| *num == choice) {
            if *domain == "custom" {
                print!("Введите домен (например, example.com): ");
                stdout().flush()?;

                let mut custom_domain = String::new();
                stdin().read_line(&mut custom_domain)?;
                let custom_domain = custom_domain.trim().to_string();

                if is_valid_domain(&custom_domain) {
                    return Ok(format_domain_with_port(&custom_domain));
                } else {
                    println!("Неверный формат домена. Используйте формат domain.com");
                    continue;
                }
            } else {
                return Ok(format_domain_with_port(domain));
            }
        } else {
            println!("Неверный выбор. Пожалуйста, выберите число от 1 до {}", DOMAIN_LIST.len());
        }
    }
}

fn is_elevated() -> bool {
    if !cfg!(target_os = "windows") {
        return false;
    }

    unsafe {
        let mut token = MaybeUninit::uninit();
        let status = OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            token.as_mut_ptr()
        );

        if status == 0 {
            return false;
        }

        let token = TokenHandle(token.assume_init());
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size: DWORD = 0;
        let elevation_ptr: *mut TOKEN_ELEVATION = &mut elevation;

        let status = GetTokenInformation(
            token.0,
            TokenElevation,
            elevation_ptr as *mut _,
            mem::size_of::<TOKEN_ELEVATION>() as DWORD,
            &mut size,
        );

        if status != 0 {
            elevation.TokenIsElevated != 0
        } else {
            false
        }
    }
}

fn request_elevation() -> io::Result<()> {
    let executable = std::env::current_exe()?;
    if let Some(executable) = executable.to_str() {
        let marker_path = std::env::temp_dir().join("bypass_checker_elevated.tmp");

        if marker_path.exists() {
            std::fs::remove_file(marker_path)?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Failed to obtain admin privileges"
            ));
        }

        std::fs::write(&marker_path, "")?;

        let quoted_executable = format!("\"{}\"", executable);
        // Use start /b to prevent new console window creation and run PowerShell hidden
        let spawn_result = Command::new("cmd")
            .args(&[
                "/C",
                "start",
                "/b",
                "powershell",
                "-WindowStyle",
                "Hidden",
                "-Command",
                &format!(
                    "Start-Process -FilePath {} -ArgumentList '--elevated' -Verb RunAs",
                    quoted_executable
                )
            ])
            .spawn();

        match &spawn_result {
            Ok(_) => {
                // Small delay to ensure the new process has started
                std::thread::sleep(std::time::Duration::from_millis(100));
                Ok(())
            },
            Err(e) => {
                let _ = std::fs::remove_file(marker_path);
                Err(io::Error::new(e.kind(), e.to_string()))
            }
        }
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Invalid executable path"
        ))
    }
}

fn main() -> AppResult<()> {
    let args: Vec<String> = std::env::args().collect();
    let is_elevated_instance = args.contains(&"--elevated".to_string());

    if is_elevated_instance {
        let marker_path = std::env::temp_dir().join("bypass_checker_elevated.tmp");
        if marker_path.exists() {
            let _ = std::fs::remove_file(marker_path);
        }
    }

    if !is_elevated() {
        println!("Требуются права администратора для корректной работы программы.");
        println!("Пожалуйста, подтвердите запрос на повышение прав.");
        match request_elevation() {
            Ok(_) => {
                // Exit immediately to close the non-elevated console window
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Ошибка при запросе прав администратора: {}", e);
                let marker_path = std::env::temp_dir().join("bypass_checker_elevated.tmp");
                if marker_path.exists() {
                    let _ = std::fs::remove_file(marker_path);
                }
                // Give user time to read the error message
                std::thread::sleep(std::time::Duration::from_secs(3));
                return Ok(());
            }
        }
    }

    let target_domain = get_domain_choice()
        .map_err(|e| AppError::IoError(format!("Ошибка при чтении ввода: {}", e)))?;

    let config = Config {
        batch_dir: PathBuf::from("pre-configs"),
        target_domain,
        process_name: String::from("winws.exe"),
        process_wait_timeout: Duration::from_secs(10),
        connection_timeout: Duration::from_secs(5),
    };

    let process_manager = ProcessManager::new();
    let network_checker = NetworkChecker::new(config.connection_timeout);

    let result = run_bypass_check(config, process_manager, &network_checker);

    println!("\nНажмите Enter для выхода...");
    io::stdout().flush().expect("Не удалось очистить буфер вывода");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Не удалось прочитать ввод");

    result
}

fn run_bypass_check(
    config: Config,
    mut process_manager: ProcessManager,
    network_checker: &NetworkChecker,
) -> AppResult<()> {
    let batch_files = config.get_batch_files()?;
    let mut success = false;

    let domain_without_port = config.target_domain.split(':').next().unwrap_or("");

    println!("\nНачинаем тестирование домена: {}", config.target_domain);
    println!("------------------------------------------------");

    println!("Проверка DPI блокировки...");
    match network_checker.check_dpi_fingerprint(domain_without_port) {
        Ok(result) => {
            println!("Результат проверки: {}", result.to_russian_string());

            if result == DPITestResult::NoDPI {
                println!("Использование DPI спуфера не требуется.");
                return Ok(());
            }

            if result == DPITestResult::NoConnection {
                println!("Проверьте подключение к интернету и правильность домена.");
                return Ok(());
            }

            println!("------------------------------------------------");
            println!("Тестируем пре-конфиги...");
        }
        Err(e) => {
            println!("Ошибка при проверке: {}", e);
            println!("Тестируем пре-конфиги...");
        }
    }

    for batch_file in batch_files {
        println!("Запуск пре-конфига: {}", batch_file.display());

        let mut child = match process_manager.run_batch_file(&batch_file) {
            Ok(child) => child,
            Err(e) => {
                eprintln!("Не удалось запустить пре-конфиг {}: {}", batch_file.display(), e);
                continue;
            }
        };

        let process_result = process_manager.wait_for_process(
            &config.process_name,
            config.process_wait_timeout,
        );

        if !process_result {
            eprintln!("{} не запустился для пре-конфига {}",
                      config.process_name, batch_file.display());
            process_manager.cleanup_process(&mut child, &config.process_name)?;
            continue;
        }

        if network_checker.test_connection(&config.target_domain)? {
            let filename = batch_file.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("неизвестный");

            println!("\n!!!!!!!!!!!!!\n[УСПЕХ] Кажется, вам подходит этот пре-конфиг - {}\n!!!!!!!!!!!!!\n\n", filename);
            process_manager.cleanup_process(&mut child, &config.process_name)?;
            success = true;
            break;
        } else {
            println!("[ПРОВАЛ] Не удалось установить соединение используя пре-конфиг: {}",
                     batch_file.display());
            process_manager.cleanup_process(&mut child, &config.process_name)?;
            continue;
        }
    }

    // Always try to clean up the process at the end
    process_manager.ensure_process_terminated(&config.process_name);

    // Double-check after a short delay
    sleep(Duration::from_millis(500));
    process_manager.ensure_process_terminated(&config.process_name);

    // If none of the pre-configs worked
    if !success {
        println!("\n------------------------------------------------");
        println!("К сожалению, ни один из пре-конфигов не помог установить соединение :(");
        println!("Попробуйте запустить BLOCKCHECK, чтобы найти нужные параметры для батника.");
    }

    Ok(())
}