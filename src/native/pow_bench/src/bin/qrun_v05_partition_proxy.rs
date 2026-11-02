//! Test-only TCP partition gate for QRun multi-process Public Alpha integration tests.
//!
//! The proxy is transparent to Noise XX: it never terminates or interprets the encrypted
//! session. Without the gate file it accepts then closes incoming connections; when the gate
//! file exists it relays bytes bidirectionally to the configured node listener.
use std::{
    env, fs, io,
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::Duration,
};

static DENIED: AtomicU64 = AtomicU64::new(0);
static RELAYED: AtomicU64 = AtomicU64::new(0);

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 1 && args[0] == "--help" {
        println!("Usage: qrun_v05_partition_proxy --listen 127.0.0.1:PORT --target 127.0.0.1:PORT --gate-file ABSOLUTE_FILE");
        return Ok(());
    }
    if args.len() != 6 || args[0] != "--listen" || args[2] != "--target" || args[4] != "--gate-file"
    {
        return Err("usage: --listen IP:PORT --target IP:PORT --gate-file ABSOLUTE_FILE".into());
    }
    let listen: SocketAddr = args[1]
        .parse()
        .map_err(|_| "--listen must be a numeric IP:PORT".to_string())?;
    let target: SocketAddr = args[3]
        .parse()
        .map_err(|_| "--target must be a numeric IP:PORT".to_string())?;
    if !listen.ip().is_loopback() || !target.ip().is_loopback() {
        return Err("test partition proxy is restricted to loopback addresses".into());
    }
    let gate = PathBuf::from(&args[5]);
    if !gate.is_absolute() || gate.file_name().is_none() {
        return Err("--gate-file must be an absolute path".into());
    }
    let listener =
        TcpListener::bind(listen).map_err(|error| format!("bind proxy {listen}: {error}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|error| error.to_string())?;
    println!(
        "qrun_partition_proxy_ready listen={listen} target={target} gate_file={}",
        gate.display()
    );

    loop {
        match listener.accept() {
            Ok((mut incoming, peer)) => {
                incoming
                    .set_nonblocking(false)
                    .map_err(|error| format!("set accepted proxy stream blocking: {error}"))?;
                let _ = incoming.set_nodelay(true);
                if fs::symlink_metadata(&gate).is_err() {
                    DENIED.fetch_add(1, Ordering::Relaxed);
                    println!(
                        "qrun_partition_proxy_denied peer={peer} denied={}",
                        DENIED.load(Ordering::Relaxed)
                    );
                    let _ = incoming.shutdown(Shutdown::Both);
                    continue;
                }
                let mut outgoing = match TcpStream::connect_timeout(&target, Duration::from_secs(2))
                {
                    Ok(stream) => stream,
                    Err(error) => {
                        eprintln!(
                            "qrun_partition_proxy_target_failed target={target} reason={error}"
                        );
                        let _ = incoming.shutdown(Shutdown::Both);
                        continue;
                    }
                };
                outgoing
                    .set_nonblocking(false)
                    .map_err(|error| format!("set proxy target stream blocking: {error}"))?;
                let _ = incoming.set_nodelay(true);
                let _ = outgoing.set_nodelay(true);
                let relay_id = RELAYED.fetch_add(1, Ordering::Relaxed) + 1;
                println!(
                    "qrun_partition_proxy_relay peer={peer} target={target} relayed={relay_id}"
                );
                thread::Builder::new()
                    .name(format!("qrun-partition-relay-{relay_id}"))
                    .spawn(move || {
                        let mut incoming_reader = match incoming.try_clone() {
                            Ok(stream) => stream,
                            Err(error) => {
                                eprintln!("qrun_partition_proxy_clone_failed direction=client_to_target reason={error}");
                                return;
                            }
                        };
                        let mut outgoing_writer = match outgoing.try_clone() {
                            Ok(stream) => stream,
                            Err(error) => {
                                eprintln!("qrun_partition_proxy_clone_failed direction=target_to_client reason={error}");
                                return;
                            }
                        };
                        let forward = thread::spawn(move || {
                            let copied = io::copy(&mut incoming_reader, &mut outgoing_writer);
                            let _ = outgoing_writer.shutdown(Shutdown::Write);
                            copied
                        });
                        let reverse = io::copy(&mut outgoing, &mut incoming);
                        let _ = incoming.shutdown(Shutdown::Write);
                        let forward = forward.join().ok().and_then(Result::ok).unwrap_or(0);
                        let reverse = reverse.unwrap_or(0);
                        println!(
                            "qrun_partition_proxy_relay_complete id={relay_id} client_to_target_bytes={forward} target_to_client_bytes={reverse}"
                        );
                    })
                    .map_err(|error| format!("spawn partition relay: {error}"))?;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(format!("accept partition proxy connection: {error}")),
        }
    }
}

fn main() {
    if let Err(error) = run() {
        eprintln!(
            "QRUN_PARTITION_PROXY_ERROR: {}",
            error.replace(['\r', '\n'], "_")
        );
        std::process::exit(2);
    }
}
