#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LanguagePreference {
    #[default]
    System,
    SimplifiedChinese,
    English,
}

impl LanguagePreference {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::SimplifiedChinese => "zh-CN",
            Self::English => "en",
        }
    }

    pub fn from_config(value: &str) -> Self {
        match value {
            "zh-CN" => Self::SimplifiedChinese,
            "en" => Self::English,
            _ => Self::System,
        }
    }

    pub fn choice(self) -> i32 {
        match self {
            Self::System => 0,
            Self::SimplifiedChinese => 1,
            Self::English => 2,
        }
    }

    pub fn from_choice(choice: i32) -> Self {
        match choice {
            1 => Self::SimplifiedChinese,
            2 => Self::English,
            _ => Self::System,
        }
    }

    pub fn resolve(self) -> Language {
        match self {
            Self::SimplifiedChinese => Language::SimplifiedChinese,
            Self::English => Language::English,
            Self::System => language_from_system_locale(system_locale().as_deref()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    SimplifiedChinese,
    English,
}

impl Language {
    pub fn slint_locale(self) -> &'static str {
        match self {
            Self::SimplifiedChinese => "zh-CN",
            Self::English => "",
        }
    }
}

fn language_from_system_locale(locale: Option<&str>) -> Language {
    let normalized = locale
        .unwrap_or_default()
        .trim()
        .replace('_', "-")
        .to_ascii_lowercase();
    if matches!(normalized.as_str(), "zh-cn" | "zh-sg" | "zh-hans")
        || normalized.starts_with("zh-hans-")
    {
        Language::SimplifiedChinese
    } else {
        Language::English
    }
}

#[cfg(windows)]
fn system_locale() -> Option<String> {
    use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
    // Windows defines LOCALE_NAME_MAX_LENGTH as 85 UTF-16 code units.
    let mut buffer = [0_u16; 85];
    // The API writes at most the supplied buffer length, including its terminating null.
    let length = unsafe { GetUserDefaultLocaleName(buffer.as_mut_ptr(), buffer.len() as i32) };
    (length > 1)
        .then(|| String::from_utf16(&buffer[..length as usize - 1]).ok())
        .flatten()
}

#[cfg(not(windows))]
fn system_locale() -> Option<String> {
    None
}

pub fn bootstrap_admin_required(language: Language) -> &'static str {
    match language {
        Language::SimplifiedChinese => {
            "FlowBrake 需要管理员权限才能拦截网络流量。\n请重新运行，并在 UAC 提示中选择“是”。"
        }
        Language::English => {
            "FlowBrake needs administrator approval to intercept network traffic.\nPlease run it again and choose Yes on the UAC prompt."
        }
    }
}

pub fn bootstrap_admin_failed(language: Language, error: &str) -> String {
    let explanation = match language {
        Language::SimplifiedChinese => "FlowBrake 无法请求管理员权限。",
        Language::English => "FlowBrake could not request administrator privileges.",
    };
    format!("{explanation}\n{error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_simplified_locales_select_chinese() {
        for locale in [
            "zh-CN",
            "ZH_cn",
            "zh-SG",
            "zh-Hans",
            "zh-Hans-CN",
            "zh_Hans_SG",
        ] {
            assert_eq!(
                language_from_system_locale(Some(locale)),
                Language::SimplifiedChinese,
                "{locale}"
            );
        }
        for locale in [
            "zh",
            "zh-TW",
            "zh-HK",
            "zh-MO",
            "zh-Hant",
            "zh-Hant-CN",
            "en",
            "en-US",
            "fr-FR",
            "unknown",
            "",
        ] {
            assert_eq!(
                language_from_system_locale(Some(locale)),
                Language::English,
                "{locale}"
            );
        }
        assert_eq!(language_from_system_locale(None), Language::English);
    }

    #[test]
    fn preferences_round_trip_and_invalid_values_follow_system() {
        for preference in [
            LanguagePreference::System,
            LanguagePreference::SimplifiedChinese,
            LanguagePreference::English,
        ] {
            assert_eq!(
                LanguagePreference::from_config(preference.as_str()),
                preference
            );
            assert_eq!(
                LanguagePreference::from_choice(preference.choice()),
                preference
            );
        }
        assert_eq!(
            LanguagePreference::from_config("invalid"),
            LanguagePreference::System
        );
        assert_eq!(
            LanguagePreference::from_choice(-1),
            LanguagePreference::System
        );
        assert_eq!(
            LanguagePreference::from_choice(3),
            LanguagePreference::System
        );
        assert_eq!(
            LanguagePreference::SimplifiedChinese.resolve(),
            Language::SimplifiedChinese
        );
        assert_eq!(LanguagePreference::English.resolve(), Language::English);
    }

    #[test]
    fn bootstrap_messages_preserve_original_diagnostics() {
        for language in [Language::SimplifiedChinese, Language::English] {
            assert!(!bootstrap_admin_required(language).is_empty());
            assert!(bootstrap_admin_failed(language, "error 5").ends_with("\nerror 5"));
        }
    }
}
