use std::{io, sync::atomic::{AtomicBool, Ordering}};

static CANCELLED: AtomicBool = AtomicBool::new(false);

pub fn cancelled() -> bool { CANCELLED.load(Ordering::Relaxed) }
pub fn request() { CANCELLED.store(true, Ordering::Relaxed) }
pub fn check() -> io::Result<()> {
    if cancelled() { Err(io::Error::other("cancelled by signal")) } else { Ok(()) }
}

#[cfg(unix)]
unsafe extern "C" fn handler(_: libc::c_int) { request() }

#[cfg(unix)]
pub fn install() -> io::Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = handler as *const () as libc::sighandler_t;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 { return Err(io::Error::last_os_error()) }
    }
    Ok(())
}

#[cfg(windows)]
unsafe extern "system" fn handler(_: u32) -> windows_sys::core::BOOL { request(); 1 }

#[cfg(windows)]
pub fn install() -> io::Result<()> {
    use windows_sys::Win32::System::Console::SetConsoleCtrlHandler;
    if unsafe { SetConsoleCtrlHandler(Some(handler), 1) } == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}
