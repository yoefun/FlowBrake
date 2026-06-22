use std::collections::HashMap;
use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Graphics::Gdi::{
    CreateCompatibleBitmap, CreateCompatibleDC, CreateSolidBrush, DeleteDC, DeleteObject, FillRect,
    GetDC, GetDIBits, ReleaseDC, SelectObject, BITMAPINFO, BITMAPINFOHEADER, BI_RGB,
    DIB_RGB_COLORS,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW,
};
use windows_sys::Win32::System::ProcessStatus::EnumProcesses;
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_sys::Win32::UI::Shell::{SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON};
use windows_sys::Win32::UI::WindowsAndMessaging::{DestroyIcon, DrawIconEx, DI_NORMAL, HICON};

const ICON_SIZE: u32 = 16;

#[derive(Debug, Default)]
pub struct ProcessMetadataCache {
    display_names: HashMap<String, String>,
}

impl ProcessMetadataCache {
    pub fn display_name_for_path(&mut self, path: &Path, fallback: &str) -> String {
        let key = path_key(path);
        if let Some(name) = self.display_names.get(&key) {
            return name.clone();
        }

        let name = friendly_display_name(path)
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| fallback.to_string());
        self.display_names.insert(key, name.clone());
        name
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessDetails {
    pub pid: u32,
    pub name: String,
    pub display_name: String,
    pub exe_path: PathBuf,
}

pub struct ProcessIcon {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

pub fn process_details(pid: u32, cache: &mut ProcessMetadataCache) -> Option<ProcessDetails> {
    let exe_path = process_image_path(pid)?;
    let name = exe_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(str::to_string)?;
    let display_name = cache.display_name_for_path(&exe_path, &name);
    Some(ProcessDetails {
        pid,
        name,
        display_name,
        exe_path,
    })
}

pub fn process_details_uncached(pid: u32) -> Option<ProcessDetails> {
    process_details(pid, &mut ProcessMetadataCache::default())
}

pub fn process_name(pid: u32) -> Option<String> {
    process_image_path(pid)?
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(str::to_string)
}

pub fn list_running_pids() -> Vec<u32> {
    let mut buffer = vec![0u32; 4096];
    loop {
        let mut bytes_returned = 0u32;
        let ok = unsafe {
            EnumProcesses(
                buffer.as_mut_ptr(),
                (buffer.len() * std::mem::size_of::<u32>()) as u32,
                &mut bytes_returned,
            )
        };
        if ok == 0 {
            return Vec::new();
        }

        let count = bytes_returned as usize / std::mem::size_of::<u32>();
        if count < buffer.len() {
            buffer.truncate(count);
            return buffer.into_iter().filter(|pid| *pid > 0).collect();
        }

        buffer.resize(buffer.len() * 2, 0);
    }
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().to_ascii_lowercase()
}

pub fn process_icon(path: &Path) -> Option<ProcessIcon> {
    let path_wide = path_to_wide(path);
    let mut shfi = SHFILEINFOW {
        hIcon: std::ptr::null_mut(),
        iIcon: 0,
        dwAttributes: 0,
        szDisplayName: [0; 260],
        szTypeName: [0; 80],
    };

    let result = unsafe {
        SHGetFileInfoW(
            path_wide.as_ptr(),
            0,
            &mut shfi,
            std::mem::size_of::<SHFILEINFOW>() as u32,
            SHGFI_ICON,
        )
    };
    if result == 0 || shfi.hIcon.is_null() {
        return None;
    }

    let icon = hicon_to_rgba(shfi.hIcon, ICON_SIZE);
    unsafe {
        DestroyIcon(shfi.hIcon);
    }
    icon
}

fn process_image_path(pid: u32) -> Option<PathBuf> {
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
    Some(PathBuf::from(OsString::from_wide(&buffer)))
}

fn friendly_display_name(path: &Path) -> Option<String> {
    version_string(path, "FileDescription")
        .or_else(|| version_string(path, "ProductName"))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn version_string(path: &Path, field: &str) -> Option<String> {
    let path_wide = path_to_wide(path);
    let size = unsafe { GetFileVersionInfoSizeW(path_wide.as_ptr(), std::ptr::null_mut()) };
    if size == 0 {
        return None;
    }

    let mut data = vec![0u8; size as usize];
    let ok = unsafe { GetFileVersionInfoW(path_wide.as_ptr(), 0, size, data.as_mut_ptr().cast()) };
    if ok == 0 {
        return None;
    }

    let translation = query_version_value(&data, "\\VarFileInfo\\Translation")?;
    if translation.len() < 4 {
        return None;
    }

    let lang = u32::from_le_bytes([
        translation[0],
        translation[1],
        translation[2],
        translation[3],
    ]);
    let subblock = format!("\\StringFileInfo\\{lang:08X}\\{field}");
    let value = query_version_value(&data, &subblock)?;
    wide_bytes_to_string(&value)
}

fn query_version_value(data: &[u8], subblock: &str) -> Option<Vec<u8>> {
    let subblock_wide = utf16_null_terminated(subblock);
    let mut pointer = std::ptr::null_mut();
    let mut length = 0u32;
    let ok = unsafe {
        VerQueryValueW(
            data.as_ptr().cast(),
            subblock_wide.as_ptr(),
            &mut pointer,
            &mut length,
        )
    };
    if ok == 0 || pointer.is_null() || length == 0 {
        return None;
    }

    let byte_len = (length as usize).saturating_mul(2);
    Some(unsafe { std::slice::from_raw_parts(pointer.cast(), byte_len) }.to_vec())
}

fn wide_bytes_to_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 2 {
        return None;
    }

    let mut units = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([chunk[0], chunk[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }

    if units.is_empty() {
        return None;
    }

    Some(OsString::from_wide(&units).to_string_lossy().into_owned())
}

fn hicon_to_rgba(icon: HICON, size: u32) -> Option<ProcessIcon> {
    unsafe {
        let screen_dc = GetDC(std::ptr::null_mut());
        if screen_dc.is_null() {
            return None;
        }

        let memory_dc = CreateCompatibleDC(screen_dc);
        if memory_dc.is_null() {
            ReleaseDC(std::ptr::null_mut(), screen_dc);
            return None;
        }

        let bitmap = CreateCompatibleBitmap(screen_dc, size as i32, size as i32);
        if bitmap.is_null() {
            DeleteDC(memory_dc);
            ReleaseDC(std::ptr::null_mut(), screen_dc);
            return None;
        }

        let old_bitmap = SelectObject(memory_dc, bitmap as _);
        let brush = CreateSolidBrush(0x00FFFFFF);
        let rect = windows_sys::Win32::Foundation::RECT {
            left: 0,
            top: 0,
            right: size as i32,
            bottom: size as i32,
        };
        FillRect(memory_dc, &rect, brush);
        DeleteObject(brush as _);

        DrawIconEx(
            memory_dc,
            0,
            0,
            icon,
            size as i32,
            size as i32,
            0,
            std::ptr::null_mut(),
            DI_NORMAL,
        );

        let mut info = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: size as i32,
                biHeight: -(size as i32),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [windows_sys::Win32::Graphics::Gdi::RGBQUAD {
                rgbBlue: 0,
                rgbGreen: 0,
                rgbRed: 0,
                rgbReserved: 0,
            }],
        };

        let mut rgba = vec![0u8; (size * size * 4) as usize];
        let lines = GetDIBits(
            memory_dc,
            bitmap,
            0,
            size,
            rgba.as_mut_ptr().cast(),
            &mut info,
            DIB_RGB_COLORS,
        );

        SelectObject(memory_dc, old_bitmap);
        DeleteObject(bitmap as _);
        DeleteDC(memory_dc);
        ReleaseDC(std::ptr::null_mut(), screen_dc);

        if lines == 0 {
            return None;
        }

        for pixel in rgba.chunks_exact_mut(4) {
            let blue = pixel[0];
            let green = pixel[1];
            let red = pixel[2];
            pixel[0] = red;
            pixel[1] = green;
            pixel[2] = blue;
            pixel[3] = if red > 245 && green > 245 && blue > 245 {
                0
            } else {
                255
            };
        }

        Some(ProcessIcon {
            width: size,
            height: size,
            rgba,
        })
    }
}

fn path_to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn utf16_null_terminated(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}
