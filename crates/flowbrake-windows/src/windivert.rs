use std::ffi::{CString, c_char, c_void};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

use libloading::Library;
use thiserror::Error;

const WINDIVERT_LAYER_NETWORK: i32 = 0;
const WINDIVERT_FLAG_IPV6: u32 = 0x0010_0000;
const WINDIVERT_FLAG_OUTBOUND: u32 = 0x0002_0000;

type WinDivertOpenFn = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> *mut c_void;
type WinDivertRecvFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, u32, *mut u32, *mut WinDivertAddress) -> bool;
type WinDivertSendFn =
    unsafe extern "C" fn(*mut c_void, *const c_void, u32, *mut u32, *mut WinDivertAddress) -> bool;
type WinDivertCloseFn = unsafe extern "C" fn(*mut c_void) -> bool;
type WinDivertCalcChecksumsFn =
    unsafe extern "C" fn(*mut c_void, u32, *mut WinDivertAddress, u64) -> bool;

#[derive(Debug, Error)]
pub enum WinDivertError {
    #[error("WinDivert.dll not found next to the executable.")]
    MissingDll,
    #[error("WinDivert64.sys not found next to the executable.")]
    MissingDriver,
    #[error("failed to load WinDivert.dll: {0}")]
    Load(#[from] libloading::Error),
    #[error("Access denied. Run as Administrator.")]
    AccessDenied,
    #[error("WinDivert driver not found.")]
    DriverNotFound,
    #[error("WinDivert failed to open (error {0}).")]
    OpenFailed(i32),
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct WinDivertAddress {
    pub timestamp: i64,
    pub flags: u32,
    pub reserved2: u32,
    pub if_idx: u32,
    pub sub_if_idx: u32,
    _padding: [u8; 56],
}

impl Default for WinDivertAddress {
    fn default() -> Self {
        Self {
            timestamp: 0,
            flags: 0,
            reserved2: 0,
            if_idx: 0,
            sub_if_idx: 0,
            _padding: [0; 56],
        }
    }
}

impl WinDivertAddress {
    pub fn is_outbound(self) -> bool {
        (self.flags & WINDIVERT_FLAG_OUTBOUND) != 0
    }

    pub fn is_ipv6(self) -> bool {
        (self.flags & WINDIVERT_FLAG_IPV6) != 0
    }
}

#[derive(Clone)]
pub struct WinDivert {
    inner: Arc<WinDivertInner>,
}

struct WinDivertInner {
    library: Library,
    handle: AtomicPtr<c_void>,
}

unsafe impl Send for WinDivert {}
unsafe impl Sync for WinDivert {}

impl WinDivert {
    pub fn open_from_dir(exe_dir: impl AsRef<Path>, filter: &str) -> Result<Self, WinDivertError> {
        let exe_dir = exe_dir.as_ref();
        let dll_path = exe_dir.join("WinDivert.dll");
        if !dll_path.exists() {
            return Err(WinDivertError::MissingDll);
        }
        if !exe_dir.join("WinDivert64.sys").exists() {
            return Err(WinDivertError::MissingDriver);
        }

        let library = unsafe { Library::new(&dll_path)? };
        let filter = CString::new(filter).expect("static filter must not contain NUL");
        let open: libloading::Symbol<WinDivertOpenFn> = unsafe { library.get(b"WinDivertOpen")? };
        let handle = unsafe { open(filter.as_ptr(), WINDIVERT_LAYER_NETWORK, 0, 0) };
        let invalid = (-1isize) as *mut c_void;
        if handle.is_null() || handle == invalid {
            let err = io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or_default();
            return Err(match err {
                5 => WinDivertError::AccessDenied,
                2 => WinDivertError::DriverNotFound,
                err => WinDivertError::OpenFailed(err),
            });
        }

        Ok(Self {
            inner: Arc::new(WinDivertInner {
                library,
                handle: AtomicPtr::new(handle),
            }),
        })
    }

    pub fn recv(&self, packet: &mut [u8]) -> Option<(usize, WinDivertAddress)> {
        let handle = self.inner.handle.load(Ordering::Acquire);
        if handle.is_null() {
            return None;
        }
        let recv: libloading::Symbol<WinDivertRecvFn> =
            unsafe { self.inner.library.get(b"WinDivertRecv").ok()? };
        let mut read_len = 0u32;
        let mut address = WinDivertAddress::default();
        let ok = unsafe {
            recv(
                handle,
                packet.as_mut_ptr().cast(),
                packet.len() as u32,
                &mut read_len,
                &mut address,
            )
        };
        ok.then_some((read_len as usize, address))
    }

    pub fn send(&self, packet: &[u8], address: &mut WinDivertAddress) -> bool {
        let handle = self.inner.handle.load(Ordering::Acquire);
        if handle.is_null() {
            return false;
        }
        let calc: libloading::Symbol<WinDivertCalcChecksumsFn> =
            match unsafe { self.inner.library.get(b"WinDivertHelperCalcChecksums") } {
                Ok(calc) => calc,
                Err(_) => return false,
            };
        let send: libloading::Symbol<WinDivertSendFn> =
            match unsafe { self.inner.library.get(b"WinDivertSend") } {
                Ok(send) => send,
                Err(_) => return false,
            };

        unsafe {
            let _ = calc(
                packet.as_ptr() as *mut c_void,
                packet.len() as u32,
                address,
                0,
            );
        }

        let mut send_len = 0u32;
        unsafe {
            send(
                handle,
                packet.as_ptr().cast(),
                packet.len() as u32,
                &mut send_len,
                address,
            )
        }
    }

    pub fn expected_paths(exe_dir: impl AsRef<Path>) -> (PathBuf, PathBuf) {
        let exe_dir = exe_dir.as_ref();
        (
            exe_dir.join("WinDivert.dll"),
            exe_dir.join("WinDivert64.sys"),
        )
    }

    pub fn close(&self) {
        self.inner.close();
    }
}

impl WinDivertInner {
    fn close(&self) {
        let handle = self.handle.swap(std::ptr::null_mut(), Ordering::AcqRel);
        if handle.is_null() {
            return;
        }
        if let Ok(close) = unsafe { self.library.get::<WinDivertCloseFn>(b"WinDivertClose") } {
            unsafe {
                let _ = close(handle);
            }
        }
    }
}

impl Drop for WinDivertInner {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windivert_address_layout_matches_csharp_size() {
        assert_eq!(std::mem::size_of::<WinDivertAddress>(), 80);
    }

    #[test]
    fn expected_paths_are_next_to_executable() {
        let (dll, sys) = WinDivert::expected_paths("C:/tmp/app");
        assert!(dll.ends_with("WinDivert.dll"));
        assert!(sys.ends_with("WinDivert64.sys"));
    }
}
