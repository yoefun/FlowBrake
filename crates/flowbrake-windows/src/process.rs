use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::path::PathBuf;

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

pub fn process_name(pid: u32) -> Option<String> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return None;
    }

    let mut buffer = vec![0u16; 32_768];
    let mut len = buffer.len() as u32;
    let ok = unsafe { QueryFullProcessImageNameW(handle, 0, buffer.as_mut_ptr(), &mut len) };
    unsafe {
        CloseHandle(handle);
    }

    if ok == 0 || len == 0 {
        return None;
    }

    buffer.truncate(len as usize);
    let path = PathBuf::from(OsString::from_wide(&buffer));
    path.file_stem()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string())
}
