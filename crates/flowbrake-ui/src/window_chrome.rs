#[cfg(target_os = "windows")]
pub fn apply_window_appearance(window: &slint::Window) -> bool {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND,
    };

    let window_handle = window.window_handle();
    let Ok(handle) = window_handle.window_handle() else {
        return false;
    };
    let RawWindowHandle::Win32(win32) = handle.as_raw() else {
        return false;
    };

    let corner_preference: i32 = DWMWCP_ROUND;
    unsafe {
        let _ = DwmSetWindowAttribute(
            win32.hwnd.get() as _,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            &corner_preference as *const _ as _,
            std::mem::size_of_val(&corner_preference) as u32,
        );
    }

    true
}

#[cfg(not(target_os = "windows"))]
pub fn apply_window_appearance(_window: &slint::Window) -> bool {
    false
}

#[cfg(target_os = "windows")]
pub fn start_window_drag(window: &slint::Window) -> bool {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::Foundation::POINT;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::ReleaseCapture;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        GetCursorPos, SendMessageW, HTCAPTION, WM_NCLBUTTONDOWN,
    };

    let window_handle = window.window_handle();
    let Ok(handle) = window_handle.window_handle() else {
        return false;
    };
    let RawWindowHandle::Win32(win32) = handle.as_raw() else {
        return false;
    };

    unsafe {
        let mut point = POINT { x: 0, y: 0 };
        let _ = GetCursorPos(&mut point);
        let lparam = ((point.y as u32) << 16) | (point.x as u32 & 0xffff);
        let _ = ReleaseCapture();
        SendMessageW(
            win32.hwnd.get() as _,
            WM_NCLBUTTONDOWN,
            HTCAPTION as usize,
            lparam as isize,
        );
    }
    true
}

#[cfg(not(target_os = "windows"))]
pub fn start_window_drag(_window: &slint::Window) -> bool {
    false
}
