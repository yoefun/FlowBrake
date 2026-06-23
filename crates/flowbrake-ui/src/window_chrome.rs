#[cfg(target_os = "windows")]
const CHROME_BORDER_COLOR: u32 = 0x00efe6df; // #dfe6ef in COLORREF (BGR)

#[cfg(target_os = "windows")]
pub struct WindowAppearanceSync {
    last_maximized: bool,
    last_width: u32,
    last_height: u32,
}

#[cfg(target_os = "windows")]
impl WindowAppearanceSync {
    pub fn new(window: &slint::Window) -> Self {
        let size = window.size();
        Self {
            last_maximized: window.is_maximized(),
            last_width: size.width,
            last_height: size.height,
        }
    }

    pub fn force(&mut self, window: &slint::Window) -> bool {
        let size = window.size();
        self.last_maximized = window.is_maximized();
        self.last_width = size.width;
        self.last_height = size.height;
        apply_window_appearance(window)
    }

    pub fn sync_if_changed(&mut self, window: &slint::Window) -> bool {
        let maximized = window.is_maximized();
        let size = window.size();
        if maximized == self.last_maximized
            && size.width == self.last_width
            && size.height == self.last_height
        {
            return false;
        }

        self.last_maximized = maximized;
        self.last_width = size.width;
        self.last_height = size.height;
        apply_window_appearance(window)
    }
}

#[cfg(not(target_os = "windows"))]
pub struct WindowAppearanceSync;

#[cfg(not(target_os = "windows"))]
impl WindowAppearanceSync {
    pub fn new(_window: &slint::Window) -> Self {
        Self
    }

    pub fn force(&mut self, _window: &slint::Window) -> bool {
        false
    }

    pub fn sync_if_changed(&mut self, _window: &slint::Window) -> bool {
        false
    }
}

#[cfg(target_os = "windows")]
pub fn apply_window_appearance(window: &slint::Window) -> bool {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::Graphics::Dwm::{
        DWMWA_BORDER_COLOR, DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_DONOTROUND, DWMWCP_ROUND,
        DwmSetWindowAttribute,
    };

    let window_handle = window.window_handle();
    let Ok(handle) = window_handle.window_handle() else {
        return false;
    };
    let RawWindowHandle::Win32(win32) = handle.as_raw() else {
        return false;
    };

    let hwnd = win32.hwnd.get() as _;
    let maximized = window.is_maximized();
    let corner_preference: i32 = if maximized {
        DWMWCP_DONOTROUND
    } else {
        DWMWCP_ROUND
    };
    let border_color: u32 = if maximized {
        0x00000000
    } else {
        CHROME_BORDER_COLOR
    };

    unsafe {
        let corner_ok = DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE as u32,
            &corner_preference as *const _ as _,
            std::mem::size_of_val(&corner_preference) as u32,
        ) == 0;
        let border_ok = DwmSetWindowAttribute(
            hwnd,
            DWMWA_BORDER_COLOR as u32,
            &border_color as *const _ as _,
            std::mem::size_of_val(&border_color) as u32,
        ) == 0;
        corner_ok && border_ok
    }
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
        GetCursorPos, HTCAPTION, SendMessageW, WM_NCLBUTTONDOWN,
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
