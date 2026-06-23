use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::ptr;

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ElevationError {
    #[error("current executable path is unavailable")]
    MissingExecutable,
    #[error("administrator approval was cancelled")]
    Cancelled,
    #[error("failed to request administrator privileges (error {0})")]
    Failed(i32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelaunchResult {
    Started,
    Cancelled,
    Failed(ElevationError),
}

pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = ptr::null_mut::<c_void>();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }

        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            ptr::addr_of_mut!(elevation).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

pub fn relaunch_as_admin(extra_args: &[&str]) -> RelaunchResult {
    let Some(exe) = current_executable() else {
        return RelaunchResult::Failed(ElevationError::MissingExecutable);
    };

    let exe_wide = path_to_wide_null(&exe);
    let args = extra_args.join(" ");
    let args_wide = if args.is_empty() {
        Vec::new()
    } else {
        string_to_wide_null(&args)
    };
    let operation = string_to_wide_null("runas");

    let result = unsafe {
        windows_sys::Win32::UI::Shell::ShellExecuteW(
            ptr::null_mut(),
            operation.as_ptr(),
            exe_wide.as_ptr(),
            if args_wide.is_empty() {
                ptr::null()
            } else {
                args_wide.as_ptr()
            },
            ptr::null(),
            windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOW,
        )
    };

    let code = result as isize;
    if code > 32 {
        return RelaunchResult::Started;
    }

    // ShellExecuteW returns the error code directly when it fails; GetLastError is unreliable.
    if code == windows_sys::Win32::Foundation::ERROR_CANCELLED as isize {
        RelaunchResult::Cancelled
    } else {
        RelaunchResult::Failed(ElevationError::Failed(code as i32))
    }
}

pub fn show_admin_required_message(message: &str) {
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};

    let title = string_to_wide_null("FlowBrake");
    let text = string_to_wide_null(message);
    unsafe {
        MessageBoxW(
            ptr::null_mut(),
            text.as_ptr(),
            title.as_ptr(),
            MB_OK | MB_ICONERROR,
        );
    }
}

pub fn runtime_dir() -> PathBuf {
    current_executable()
        .and_then(|path| path.parent().map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn current_executable() -> Option<PathBuf> {
    std::env::current_exe().ok().or_else(|| {
        std::env::args_os()
            .next()
            .map(PathBuf::from)
            .and_then(|path| {
                if path.is_absolute() {
                    Some(path)
                } else {
                    std::env::current_dir().ok().map(|cwd| cwd.join(path))
                }
            })
    })
}

fn path_to_wide_null(path: &std::path::Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn string_to_wide_null(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn elevation_check_does_not_panic() {
        let _ = is_elevated();
    }

    #[test]
    fn runtime_dir_points_next_to_executable() {
        let dir = runtime_dir();
        assert!(dir.is_absolute() || dir.as_os_str() == ".");
    }
}
