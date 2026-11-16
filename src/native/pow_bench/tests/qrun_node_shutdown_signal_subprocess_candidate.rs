//! CP-0489: exercise the real QRun node executable with an OS-delivered shutdown signal.
//!
//! Every listener is bound to a freshly reserved loopback port and the node uses a throwaway
//! deterministic test identity/store. This test never uses public endpoints or existing chain data.

use ai_native_l1_pow_bench::transaction_auth::Ed25519TransactionSigner;
use std::{
    fs,
    io::{BufRead, BufReader},
    net::TcpListener,
    path::PathBuf,
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};

static NEXT_DIR: AtomicU64 = AtomicU64::new(1);
const READY_MARKER: &str = "qrun_pow_local_block_ready";
const CLEANUP_MARKER: &str = "qrun_node_lifecycle_cleanup_complete";

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "qrun_cp0489_node_signal_{}_{}",
            std::process::id(),
            NEXT_DIR.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).expect("create isolated node test directory");
        Self(path)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn reserve_three_loopback_addresses() -> [std::net::SocketAddr; 3] {
    let reservations = (0..3)
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("reserve loopback test listener"))
        .collect::<Vec<_>>();
    let addresses = [
        reservations[0].local_addr().unwrap(),
        reservations[1].local_addr().unwrap(),
        reservations[2].local_addr().unwrap(),
    ];
    assert_ne!(addresses[0], addresses[1]);
    assert_ne!(addresses[0], addresses[2]);
    assert_ne!(addresses[1], addresses[2]);
    drop(reservations);
    addresses
}

fn spawn_reader<R: std::io::Read + Send + 'static>(
    reader: R,
    stream_name: &'static str,
    sender: mpsc::Sender<String>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        for line in BufReader::new(reader).lines() {
            match line {
                Ok(line) => {
                    let _ = sender.send(format!("{stream_name}: {line}"));
                }
                Err(error) => {
                    let _ = sender.send(format!("{stream_name}: <read error: {error}>"));
                    break;
                }
            }
        }
    })
}

fn recv_line(receiver: &Receiver<String>, timeout: Duration, output: &mut Vec<String>) -> bool {
    match receiver.recv_timeout(timeout) {
        Ok(line) => {
            output.push(line);
            true
        }
        Err(_) => false,
    }
}

fn start_real_qrun_node() -> (
    TestDir,
    Child,
    Receiver<String>,
    thread::JoinHandle<()>,
    thread::JoinHandle<()>,
) {
    let directory = TestDir::new();
    let root = directory.0.clone();

    let signer = Ed25519TransactionSigner::from_seed([0x5B; 32]);
    let owner_account = signer.account_id();
    let owner_public_key = signer.public_key();
    let network_id = [0x8E; 32];
    let [rpc, tx, block] = reserve_three_loopback_addresses();

    let mut command = Command::new(env!("CARGO_BIN_EXE_qrun_v05_pow_local_node"));
    command
        .arg("--local-testnet")
        .arg("--network-id-hex")
        .arg(hex(&network_id))
        .arg("--owner-account-id-hex")
        .arg(hex(&owner_account))
        .arg("--owner-public-key-hex")
        .arg(hex(&owner_public_key))
        .arg("--data-dir")
        .arg(&root)
        .arg("--rpc-listen")
        .arg(rpc.to_string())
        .arg("--tx-listen")
        .arg(tx.to_string())
        .arg("--block-listen")
        .arg(block.to_string())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NEW_PROCESS_GROUP permits a targeted CTRL_BREAK_EVENT without signalling
        // the parent test runner or unrelated sibling processes on the shared CI console.
        command.creation_flags(0x0000_0200);
    }

    let mut child = command
        .spawn()
        .expect("spawn real qrun_v05_pow_local_node binary");
    let stdout = child.stdout.take().expect("capture node stdout");
    let stderr = child.stderr.take().expect("capture node stderr");
    let (sender, receiver) = mpsc::channel();
    let stdout_reader = spawn_reader(stdout, "stdout", sender.clone());
    let stderr_reader = spawn_reader(stderr, "stderr", sender);
    (directory, child, receiver, stdout_reader, stderr_reader)
}

#[cfg(unix)]
fn deliver_shutdown_signal(child: &Child, signal: i32) -> std::io::Result<()> {
    let result = unsafe { libc::kill(child.id() as libc::pid_t, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn deliver_shutdown_signal(child: &Child, _signal: u32) -> std::io::Result<()> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GenerateConsoleCtrlEvent(control_type: u32, process_group_id: u32) -> i32;
    }
    // CTRL_BREAK_EVENT is targetable to the child's CREATE_NEW_PROCESS_GROUP id.
    let result = unsafe { GenerateConsoleCtrlEvent(1, child.id()) };
    if result != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn finish_reader_threads(
    stdout_reader: thread::JoinHandle<()>,
    stderr_reader: thread::JoinHandle<()>,
    receiver: &Receiver<String>,
    output: &mut Vec<String>,
) {
    stdout_reader.join().expect("join QRun stdout reader");
    stderr_reader.join().expect("join QRun stderr reader");
    while let Ok(line) = receiver.try_recv() {
        output.push(line);
    }
}

fn run_node_signal_case(signal_label: &str) {
    let (_directory, mut child, receiver, stdout_reader, stderr_reader) = start_real_qrun_node();
    let mut output = Vec::new();
    let ready_deadline = Instant::now() + Duration::from_secs(30);
    let mut ready = false;

    while Instant::now() < ready_deadline {
        if let Some(status) = child.try_wait().expect("poll QRun node startup") {
            finish_reader_threads(stdout_reader, stderr_reader, &receiver, &mut output);
            panic!(
                "QRun node exited before registering its shutdown handlers ({signal_label}); status={status:?}; output={output:#?}"
            );
        }
        if recv_line(&receiver, Duration::from_millis(50), &mut output)
            && output
                .last()
                .is_some_and(|line| line.contains(READY_MARKER))
        {
            ready = true;
            break;
        }
    }

    if !ready {
        let _ = child.kill();
        let status = child.wait().expect("reap QRun node that failed to start");
        finish_reader_threads(stdout_reader, stderr_reader, &receiver, &mut output);
        panic!(
            "QRun node did not reach the post-bind ready marker for {signal_label}; status={status:?}; output={output:#?}"
        );
    }

    #[cfg(unix)]
    let signal_result = {
        let signal = if signal_label == "SIGINT" {
            libc::SIGINT
        } else {
            libc::SIGTERM
        };
        deliver_shutdown_signal(&child, signal)
    };
    #[cfg(windows)]
    let signal_result = deliver_shutdown_signal(&child, 1);

    if let Err(error) = signal_result {
        let _ = child.kill();
        let status = child
            .wait()
            .expect("reap QRun node after signal-delivery error");
        finish_reader_threads(stdout_reader, stderr_reader, &receiver, &mut output);
        panic!(
            "failed to deliver {signal_label} to QRun node; error={error}; status={status:?}; output={output:#?}"
        );
    }

    let shutdown_deadline = Instant::now() + Duration::from_secs(10);
    let status: ExitStatus = loop {
        if let Some(status) = child.try_wait().expect("poll QRun node graceful exit") {
            break status;
        }
        if Instant::now() >= shutdown_deadline {
            let _ = child.kill();
            let killed_status = child.wait().expect("reap timed-out QRun node child");
            finish_reader_threads(stdout_reader, stderr_reader, &receiver, &mut output);
            panic!(
                "QRun node did not exit within 10 seconds after {signal_label}; forced status={killed_status:?}; output={output:#?}"
            );
        }
        let _ = recv_line(&receiver, Duration::from_millis(50), &mut output);
    };

    finish_reader_threads(stdout_reader, stderr_reader, &receiver, &mut output);
    assert_eq!(
        status.code(),
        Some(0),
        "QRun node exited non-zero after {signal_label}; output={output:#?}"
    );
    assert!(
        output
            .iter()
            .any(|line| line.contains("qrun_node_shutdown_requested")),
        "QRun node did not acknowledge {signal_label}; output={output:#?}"
    );
    assert!(
        output.iter().any(|line| line.contains(CLEANUP_MARKER)),
        "QRun node did not report cleanup and signal-handler restoration after {signal_label}; output={output:#?}"
    );
}

#[test]
fn real_qrun_node_exits_cleanly_after_os_shutdown_signal() {
    #[cfg(unix)]
    {
        run_node_signal_case("SIGINT");
        run_node_signal_case("SIGTERM");
    }
    #[cfg(windows)]
    {
        run_node_signal_case("CTRL_BREAK_EVENT");
    }
    #[cfg(not(any(unix, windows)))]
    {
        panic!("this target does not expose a supported QRun process-signal test");
    }
}
