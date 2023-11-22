use std::process::{ Command, Stdio };
use std::io::{ BufRead, BufReader };
use std::sync::{ Arc, Mutex };
use reqwest::Client;
use tokio::task;
use std::env;
use std::process::exit;
use aes::Aes128;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

type Aes128Cbc = Cbc<Aes128, Pkcs7>;

#[macro_use]
extern crate litcrypt;

use_litcrypt!();

#[tokio::main]
async fn main() -> Result<(), ()> {
    let shared_var = Arc::new(Mutex::new(Vec::new()));
    let shared_var_fr = Arc::new(Mutex::new(Vec::new()));
    let shared_var_fwr = Arc::new(Mutex::new(Vec::new()));

    let args: Vec<String> = env::args().collect();

    if args.len() > 1 {
        let arg1 = &args[1];
        println!("The value of argv[1] is: {}", arg1);
    } else {
        println!("No value provided for argv[1]");
        exit(1);
    }

    let handle_proc = task::spawn({
        let shared_var = shared_var.clone();
        async move {
            let mut cmd = Command::new("bpftrace")
                .arg("-q")
                .arg("-e")
                .arg(
                    "tracepoint:syscalls:sys_enter_execve { printf(\"%d %d %d %s \", tid, curtask->parent->pid, uid, str(args->filename)); join(args->argv); }"
                )
                .stdout(Stdio::piped())
                .spawn()
                .expect("Failed to start bpftrace");

            let stdout = cmd.stdout.take().unwrap();
            let reader = BufReader::new(stdout);

            for line in reader.lines() {
                let mut shared_var = shared_var.lock().unwrap();
                shared_var.push(line.unwrap());
            }

            cmd.wait().unwrap();
        }
    });

    let handle_file_read = task::spawn({
        let shared_var_fr = shared_var_fr.clone();
        async move {
            let mut cmd = Command::new("bpftrace")
                .arg("-q")
                .arg("-e")
                .arg(
                    "tracepoint:syscalls:sys_enter_openat /pid != 0/ { $mode = \"UNKNOWN\"; if ((args->flags & 1) == 0) { $mode = \"READ\"; } if ((args->flags & 1) == 1) { $mode = \"WRITE\"; } if ((args->flags & 2) == 2) { $mode = \"READ/WRITE\"; } printf(\"%s[%d]<-[%d] opened file: %s in %s mode\\n\", comm, pid, curtask->parent->pid, str(args->filename), $mode); }"
                )
                .stdout(Stdio::piped())
                .spawn()
                .expect("Failed to start bpftrace");

            let stdout = cmd.stdout.take().unwrap();
            let reader = BufReader::new(stdout);

            for line in reader.lines() {
                if let Ok(line) = line {
                    if line.contains("flag") {
                        let mut shared_var_fr = shared_var_fr.lock().unwrap();
                        shared_var_fr.push(line);
                    }
                }
            }

            cmd.wait().unwrap();
        }
    });

    let handle_file_write = task::spawn({
        let shared_var_fwr = shared_var_fwr.clone();
        async move {
            let mut cmd = Command::new("bpftrace")
                .arg("-q")
                .arg("-e")
                .arg(
                    "tracepoint:syscalls:sys_enter_openat /pid != 0 && (args->flags & 64) == 64/ { $mode = \"UNKNOWN\"; if ((args->flags & 1) == 0) { $mode = \"READ\"; } if ((args->flags & 1) == 1) { $mode = \"WRITE\"; } if ((args->flags & 2) == 2) { $mode = \"READ/WRITE\"; } printf(\"%s[%d]<-[%d] opened file: %s in %s mode\\n\", comm, pid, curtask->parent->pid, str(args->filename), $mode); }"
                )
                .stdout(Stdio::piped())
                .spawn()
                .expect("Failed to start bpftrace");

            let stdout = cmd.stdout.take().unwrap();
            let reader = BufReader::new(stdout);

            for line in reader.lines() {
                let mut shared_var_fwr = shared_var_fwr.lock().unwrap();
                shared_var_fwr.push(line.unwrap());
            }

            cmd.wait().unwrap();
        }
    });

    let handle_proc_ingest = task::spawn({
        let shared_var = shared_var.clone();
        let args = args.clone();
        async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                let shared_var_str = {
                    let mut shared_var_lock = shared_var.lock().unwrap();
                    let shared_var_str = shared_var_lock.join("\n");
                    shared_var_lock.clear();
                    shared_var_str
                };

                if shared_var_str.is_empty() {
                    continue;
                }

                let key = lc!(env!("KEY"));
                let iv = lc!(env!("IV"));
                let cipher = Aes128Cbc::new_from_slices(key.as_bytes(), iv.as_bytes()).unwrap();
                let ciphertext = cipher.encrypt_vec(shared_var_str.as_bytes());

                let client = Client::new();
                let _ = client
                    .post(lc!(format!("https://{}/ingest/", env!("DOMAIN"))) + args[1].as_str())
                    .body(ciphertext)
                    .send().await;
            }
        }
    });

    let handle_proc_ingest_fr = task::spawn({
        let shared_var_fr = shared_var_fr.clone();
        let args = args.clone();
        async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                let shared_var_str = {
                    let mut shared_var_lock = shared_var_fr.lock().unwrap();
                    let shared_var_str = shared_var_lock.join("\n");
                    shared_var_lock.clear();
                    shared_var_str
                };

                if shared_var_str.is_empty() {
                    continue;
                }

                let key = lc!(env!("KEY"));
                let iv = lc!(env!("IV"));
                let cipher = Aes128Cbc::new_from_slices(key.as_bytes(), iv.as_bytes()).unwrap();
                let ciphertext = cipher.encrypt_vec(shared_var_str.as_bytes());

                let client = Client::new();
                let _ = client
                    .post(lc!(format!("https://{}/ingest_fr/", env!("DOMAIN"))) + args[1].as_str())
                    .body(ciphertext)
                    .send().await;
            }
        }
    });

    let handle_proc_ingest_fwr = task::spawn({
        let shared_var_fwr = shared_var_fwr.clone();
        let args = args.clone();
        async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                let shared_var_str = {
                    let mut shared_var_lock = shared_var_fwr.lock().unwrap();
                    let shared_var_str = shared_var_lock.join("\n");
                    shared_var_lock.clear();
                    shared_var_str
                };

                if shared_var_str.is_empty() {
                    continue;
                }

                let key = lc!(env!("KEY"));
                let iv = lc!(env!("IV"));
                let cipher = Aes128Cbc::new_from_slices(key.as_bytes(), iv.as_bytes()).unwrap();
                let ciphertext = cipher.encrypt_vec(shared_var_str.as_bytes());

                let client = Client::new();
                let _ = client
                    .post(lc!(format!("https://{}/ingest_fwr/", env!("DOMAIN"))) + args[1].as_str())
                    .body(ciphertext)
                    .send().await;
            }
        }
    });

    let _ = tokio::join!(handle_proc, handle_file_write, handle_file_read, handle_proc_ingest, handle_proc_ingest_fr, handle_proc_ingest_fwr);

    Ok(())
}
