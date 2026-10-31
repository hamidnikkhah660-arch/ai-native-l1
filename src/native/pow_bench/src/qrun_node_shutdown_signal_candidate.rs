//! CP-0488 candidate process-signal bridge for the QRun local node event loop.
//!
//! The OS callback only sets an atomic flag. All node cleanup, including optional off-host Anchor
//! daemon shutdown and joining, remains on the ordinary node thread. Unix handles SIGINT/SIGTERM;
//! Windows handles console Ctrl+C/Ctrl+Break. Forced termination is not intercepted.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);
static HANDLER_INSTALLED: AtomicBool = AtomicBool::new(false);

fn mark_shutdown_requested() {
    SHUTDOWN_REQUESTED.store(true, Ordering::Release);
}

#[cfg(unix)]
extern "C" fn qrun_unix_shutdown_signal_handler(_signal: libc::c_int) {
    // Keep the asynchronous callback limited to an atomic flag update.
    mark_shutdown_requested();
}

#[cfg(windows)]
extern "system" fn qrun_windows_console_control_handler(control_type: u32) -> i32 {
    // CTRL_C_EVENT = 0; CTRL_BREAK_EVENT = 1. Do not claim close/logoff/shutdown events:
    // Windows may terminate the process after a short console-handler deadline.
    match control_type {
        0 | 1 => {
            mark_shutdown_requested();
            1
        }
        _ => 0,
    }
}

/// Exclusive process-wide signal registration for one QRun node event loop.
///
/// This type does not spawn threads, bind sockets, or start the off-host Anchor daemon. Its OS
/// callback never takes locks or performs I/O. Drop restores the handlers that were active before
/// installation; explicit `uninstall` reports restoration errors.
pub struct QRunNodeShutdownSignalCandidate {
    #[cfg(unix)]
    previous_sigint: std::mem::MaybeUninit<libc::sigaction>,
    #[cfg(unix)]
    previous_sigterm: std::mem::MaybeUninit<libc::sigaction>,
    active: bool,
}

impl QRunNodeShutdownSignalCandidate {
    /// Install the platform shutdown callback. Only one registration may be active per process.
    pub fn install() -> io::Result<Self> {
        if HANDLER_INSTALLED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "QRun process shutdown handler is already installed",
            ));
        }
        SHUTDOWN_REQUESTED.store(false, Ordering::Release);

        #[cfg(unix)]
        let (previous_sigint, previous_sigterm) = match install_unix_handlers() {
            Ok(previous) => previous,
            Err(error) => {
                HANDLER_INSTALLED.store(false, Ordering::Release);
                SHUTDOWN_REQUESTED.store(false, Ordering::Release);
                return Err(error);
            }
        };

        #[cfg(windows)]
        if let Err(error) = install_windows_handler() {
            HANDLER_INSTALLED.store(false, Ordering::Release);
            SHUTDOWN_REQUESTED.store(false, Ordering::Release);
            return Err(error);
        }

        #[cfg(not(any(unix, windows)))]
        {
            HANDLER_INSTALLED.store(false, Ordering::Release);
            SHUTDOWN_REQUESTED.store(false, Ordering::Release);
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "QRun graceful process signals are unsupported on this target",
            ));
        }

        Ok(Self {
            #[cfg(unix)]
            previous_sigint,
            #[cfg(unix)]
            previous_sigterm,
            active: true,
        })
    }

    /// Whether the OS callback has requested graceful node shutdown.
    pub fn is_shutdown_requested(&self) -> bool {
        SHUTDOWN_REQUESTED.load(Ordering::Acquire)
    }

    /// Restore the process handlers and release the process-wide registration.
    pub fn uninstall(mut self) -> io::Result<()> {
        self.restore()
    }

    fn restore(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }

        #[cfg(unix)]
        unsafe {
            if libc::sigaction(
                libc::SIGTERM,
                self.previous_sigterm.as_ptr(),
                std::ptr::null_mut(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::sigaction(
                libc::SIGINT,
                self.previous_sigint.as_ptr(),
                std::ptr::null_mut(),
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
        }

        #[cfg(windows)]
        unsafe {
            if SetConsoleCtrlHandler(Some(qrun_windows_console_control_handler), 0) == 0 {
                return Err(io::Error::last_os_error());
            }
        }

        self.active = false;
        SHUTDOWN_REQUESTED.store(false, Ordering::Release);
        HANDLER_INSTALLED.store(false, Ordering::Release);
        Ok(())
    }
}

impl Drop for QRunNodeShutdownSignalCandidate {
    fn drop(&mut self) {
        // Drop is best-effort; code requiring an observable result must call uninstall explicitly.
        let _ = self.restore();
    }
}

#[cfg(unix)]
fn install_unix_handlers() -> io::Result<(
    std::mem::MaybeUninit<libc::sigaction>,
    std::mem::MaybeUninit<libc::sigaction>,
)> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = qrun_unix_shutdown_signal_handler as libc::sighandler_t;
    // Restart interruptible blocking socket operations; the loop observes the atomic flag after
    // the current bounded handler returns instead of treating the signal as a request failure.
    action.sa_flags = libc::SA_RESTART;
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut previous_sigint = std::mem::MaybeUninit::uninit();
    if unsafe { libc::sigaction(libc::SIGINT, &action, previous_sigint.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut previous_sigterm = std::mem::MaybeUninit::uninit();
    if unsafe { libc::sigaction(libc::SIGTERM, &action, previous_sigterm.as_mut_ptr()) } != 0 {
        // Roll back the first registration if the second one cannot be installed.
        let _ = unsafe {
            libc::sigaction(libc::SIGINT, previous_sigint.as_ptr(), std::ptr::null_mut())
        };
        return Err(io::Error::last_os_error());
    }

    Ok((previous_sigint, previous_sigterm))
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn SetConsoleCtrlHandler(handler: Option<extern "system" fn(u32) -> i32>, add: i32) -> i32;
}

#[cfg(windows)]
fn install_windows_handler() -> io::Result<()> {
    let installed = unsafe { SetConsoleCtrlHandler(Some(qrun_windows_console_control_handler), 1) };
    if installed == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_is_exclusive_and_shutdown_flag_is_reset_on_reinstall() {
        let signal = QRunNodeShutdownSignalCandidate::install().unwrap();
        assert!(!signal.is_shutdown_requested());

        assert!(matches!(
            QRunNodeShutdownSignalCandidate::install(),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists
        ));

        #[cfg(unix)]
        qrun_unix_shutdown_signal_handler(libc::SIGINT);
        #[cfg(windows)]
        {
            assert_eq!(qrun_windows_console_control_handler(2), 0);
            assert!(!signal.is_shutdown_requested());
            assert_eq!(qrun_windows_console_control_handler(0), 1);
        }
        assert!(signal.is_shutdown_requested());
        signal.uninstall().unwrap();

        let replacement = QRunNodeShutdownSignalCandidate::install().unwrap();
        assert!(!replacement.is_shutdown_requested());
        replacement.uninstall().unwrap();
    }
}
