use std::thread::sleep;
use std::path::PathBuf;
use std::time::Duration;
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;

mod config;
mod process;
mod network;
mod error;

use config::Config;
use error::AppResult;
use process::ProcessManager;
use network::NetworkChecker;

fn is_elevated() -> bool {
    if cfg!(target_os = "windows") {
        match Command::new("net")
            .args(&["session"])
            .output() {
            Ok(output) => output.status.success(),
            Err(_) => false
        }
    } else {
        false
    }
}

fn request_elevation() -> io::Result<()> {
    let executable = std::env::current_exe()?;
    if let Some(executable) = executable.to_str() {
        Command::new("powershell")
            .args(&[
                "Start-Process",
                executable,
                "-Verb",
                "RunAs"
            ])
            .spawn()?;
    }
    Ok(())
}

fn main() -> AppResult<()> {
    if !is_elevated() {
        println!("Требуются права администратора для корректной работы программы.");
        println!("Пожалуйста, подтвердите запрос на повышение прав.");
        if let Err(e) = request_elevation() {
            eprintln!("Ошибка при запросе прав администратора: {}", e);
        }
        return Ok(());
    }

    let config = Config {
        batch_dir: PathBuf::from("pre-configs"),
        target_domain: String::from("discord.com:443"),
        process_name: String::from("winws.exe"),
        process_wait_timeout: Duration::from_secs(10),
        connection_timeout: Duration::from_secs(5),
    };

    let process_manager = ProcessManager::new();
    let network_checker = NetworkChecker::new();

    let result = run_bypass_check(config, process_manager, network_checker);

    println!("\nНажмите Enter для выхода...");
    io::stdout().flush().expect("Не удалось очистить буфер вывода");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Не удалось прочитать ввод");

    result
}

fn run_bypass_check(
    config: Config,
    mut process_manager: ProcessManager,
    network_checker: NetworkChecker,
) -> AppResult<()> {
    let batch_files = config.get_batch_files()?;
    let mut success = false;

    for batch_file in batch_files {
        println!("Запуск конфига: {}", batch_file.display());

        let mut child = match process_manager.run_batch_file(&batch_file) {
            Ok(child) => child,
            Err(e) => {
                eprintln!("Не удалось запустить конфиг {}: {}", batch_file.display(), e);
                continue;
            }
        };

        let process_result = process_manager.wait_for_process(
            &config.process_name,
            config.process_wait_timeout,
        );

        if !process_result {
            eprintln!("{} не запустился для конфига {}",
                      config.process_name, batch_file.display());
            process_manager.cleanup_process(&mut child, &config.process_name)?;
            continue;
        }

        if network_checker.test_connection(&config.target_domain, config.connection_timeout)? {
            let filename = batch_file.file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("неизвестный");

            println!("[УСПЕХ] Кажется, вам подходит этот пре-конфиг - {}", filename);
            process_manager.cleanup_process(&mut child, &config.process_name)?;
            success = true;
            break;
        } else {
            println!("[ПРОВАЛ] Не удалось установить соединение используя конфиг: {}",
                     batch_file.display());
            println!("Пробую другой.");
            process_manager.cleanup_process(&mut child, &config.process_name)?;
            continue;
        }
    }

    // Always try to clean up the process at the end, regardless of success
    process_manager.ensure_process_terminated(&config.process_name);

    // Double-check after a short delay
    sleep(Duration::from_millis(500));
    process_manager.ensure_process_terminated(&config.process_name);

    Ok(())
}