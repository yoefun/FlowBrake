use std::ffi::{CString, c_char, c_void};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicPtr, Ordering};

use libloading::Library;
use thiserror::Error;

const WINDIVERT_LAYER_NETWORK: i32 = 0;
const WINDIVERT_LAYER_SOCKET: i32 = 3;
const WINDIVERT_FLAG_DROP: u64 = 0x0002;
const WINDIVERT_FLAG_RECV_ONLY: u64 = 0x0004;
const WINDIVERT_FLAG_LOOPBACK: u32 = 0x0004_0000;
const WINDIVERT_FLAG_IPV6: u32 = 0x0010_0000;
const WINDIVERT_FLAG_OUTBOUND: u32 = 0x0002_0000;
const WINDIVERT_SHUTDOWN_RECV: i32 = 1;

type WinDivertOpenFn = unsafe extern "C" fn(*const c_char, i32, i16, u64) -> *mut c_void;
type WinDivertRecvFn =
    unsafe extern "C" fn(*mut c_void, *mut c_void, u32, *mut u32, *mut WinDivertAddress) -> i32;
type WinDivertSendFn =
    unsafe extern "C" fn(*mut c_void, *const c_void, u32, *mut u32, *mut WinDivertAddress) -> i32;
type WinDivertShutdownFn = unsafe extern "C" fn(*mut c_void, i32) -> i32;
type WinDivertCloseFn = unsafe extern "C" fn(*mut c_void) -> i32;
type WinDivertCalcChecksumsFn =
    unsafe extern "C" fn(*mut c_void, u32, *mut WinDivertAddress, u64) -> i32;

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
    #[error("WinDivert filter contains a NUL byte.")]
    InvalidFilter,
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
    pub fn is_loopback(self) -> bool {
        (self.flags & WINDIVERT_FLAG_LOOPBACK) != 0
    }
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
        Self::open(exe_dir.as_ref(), filter, WINDIVERT_LAYER_NETWORK, 0)
    }

    pub fn open_socket_block_from_dir(
        exe_dir: impl AsRef<Path>,
        filter: &str,
    ) -> Result<Self, WinDivertError> {
        Self::open(
            exe_dir.as_ref(),
            filter,
            WINDIVERT_LAYER_SOCKET,
            WINDIVERT_FLAG_DROP | WINDIVERT_FLAG_RECV_ONLY,
        )
    }

    fn open(exe_dir: &Path, filter: &str, layer: i32, flags: u64) -> Result<Self, WinDivertError> {
        let dll_path = exe_dir.join("WinDivert.dll");
        if !dll_path.exists() {
            return Err(WinDivertError::MissingDll);
        }
        if !exe_dir.join("WinDivert64.sys").exists() {
            return Err(WinDivertError::MissingDriver);
        }

        let library = unsafe { Library::new(&dll_path)? };
        let filter = CString::new(filter).map_err(|_| WinDivertError::InvalidFilter)?;
        let open: libloading::Symbol<WinDivertOpenFn> = unsafe { library.get(b"WinDivertOpen")? };
        let handle = unsafe { open(filter.as_ptr(), layer, 0, flags) };
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
        self.recv_result(packet).ok()
    }

    pub fn recv_result(&self, packet: &mut [u8]) -> io::Result<(usize, WinDivertAddress)> {
        let handle = self.inner.valid_handle()?;
        let packet_len = u32::try_from(packet.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "packet buffer exceeds u32")
        })?;
        let recv: libloading::Symbol<WinDivertRecvFn> =
            unsafe { self.inner.library.get(b"WinDivertRecv") }.map_err(io::Error::other)?;
        let mut read_len = 0u32;
        let mut address = WinDivertAddress::default();
        let ok = unsafe {
            recv(
                handle,
                packet.as_mut_ptr().cast(),
                packet_len,
                &mut read_len,
                &mut address,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if read_len > packet_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "WinDivertRecv returned a length larger than the packet buffer",
            ));
        }
        Ok((read_len as usize, address))
    }

    pub fn send(&self, packet: &[u8], address: &mut WinDivertAddress) -> bool {
        self.send_result(packet, address).is_ok()
    }

    pub fn send_result(&self, packet: &[u8], address: &mut WinDivertAddress) -> io::Result<()> {
        let handle = self.inner.valid_handle()?;
        let packet_len = u32::try_from(packet.len()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "packet length exceeds u32")
        })?;
        let calc: libloading::Symbol<WinDivertCalcChecksumsFn> =
            unsafe { self.inner.library.get(b"WinDivertHelperCalcChecksums") }
                .map_err(io::Error::other)?;
        let send: libloading::Symbol<WinDivertSendFn> =
            unsafe { self.inner.library.get(b"WinDivertSend") }.map_err(io::Error::other)?;

        unsafe {
            let _ = calc(packet.as_ptr() as *mut c_void, packet_len, address, 0);
        }

        let mut send_len = 0u32;
        let ok = unsafe {
            send(
                handle,
                packet.as_ptr().cast(),
                packet_len,
                &mut send_len,
                address,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        if send_len != packet_len {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("WinDivertSend sent {send_len} of {packet_len} bytes"),
            ));
        }
        Ok(())
    }

    pub fn shutdown_recv(&self) -> io::Result<()> {
        let handle = self.inner.valid_handle()?;
        let shutdown: libloading::Symbol<WinDivertShutdownFn> =
            unsafe { self.inner.library.get(b"WinDivertShutdown") }.map_err(io::Error::other)?;
        if unsafe { shutdown(handle, WINDIVERT_SHUTDOWN_RECV) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
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
    fn valid_handle(&self) -> io::Result<*mut c_void> {
        let handle = self.handle.load(Ordering::Acquire);
        if handle.is_null() || handle == (-1isize) as *mut c_void {
            return Err(io::Error::from_raw_os_error(6));
        }
        Ok(handle)
    }

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

    #[test]
    fn closed_and_invalid_handles_report_windows_invalid_handle() {
        for handle in [std::ptr::null_mut(), (-1isize) as *mut c_void] {
            let divert = WinDivert {
                inner: Arc::new(WinDivertInner {
                    library: unsafe { Library::new("kernel32.dll").unwrap() },
                    handle: AtomicPtr::new(handle),
                }),
            };
            let mut packet = [0u8; 40];
            let mut address = WinDivertAddress::default();
            assert_eq!(
                divert.recv_result(&mut packet).unwrap_err().raw_os_error(),
                Some(6)
            );
            assert_eq!(
                divert
                    .send_result(&packet, &mut address)
                    .unwrap_err()
                    .raw_os_error(),
                Some(6)
            );
            assert_eq!(divert.shutdown_recv().unwrap_err().raw_os_error(), Some(6));
            assert!(divert.recv(&mut packet).is_none());
            assert!(!divert.send(&packet, &mut address));
        }
    }
}
