//! Fuzzy process-table search and scroll locate logic for the UI layer.
#![allow(dead_code)]

use flowbrake_core::{ProcessRow as CoreProcessRow, RowKind};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct ProcessSearchLocate {
    pub matched_row_index: Option<usize>,
    pub scroll_offset_px: f32,
    pub needs_row_rebuild: bool,
}

impl Default for ProcessSearchLocate {
    fn default() -> Self {
        Self {
            matched_row_index: None,
            scroll_offset_px: 0.0,
            needs_row_rebuild: false,
        }
    }
}

pub(crate) fn fuzzy_match(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return true;
    }

    let haystack = haystack.to_lowercase();
    let needle = needle.to_lowercase();
    let mut hay_chars = haystack.chars();

    for needle_char in needle.chars() {
        loop {
            match hay_chars.next() {
                Some(hay_char) if hay_char == needle_char => break,
                Some(_) => continue,
                None => return false,
            }
        }
    }

    true
}

pub(crate) fn row_search_texts(row: &CoreProcessRow, computer_name: &str) -> Vec<String> {
    match &row.kind {
        RowKind::Global => vec![computer_name.to_string()],
        RowKind::Group {
            process_name,
            display_name,
            pids,
            ..
        } => {
            let mut values = vec![display_name.clone(), process_name.clone()];
            values.extend(pids.iter().map(|pid| pid.to_string()));
            values
        }
        RowKind::Child {
            process_name,
            display_name,
            pid,
            ..
        } => vec![
            format!("PID {pid}"),
            pid.to_string(),
            display_name.clone(),
            process_name.clone(),
        ],
    }
}

pub(crate) fn row_matches_search(row: &CoreProcessRow, search: &str, computer_name: &str) -> bool {
    row_search_texts(row, computer_name)
        .iter()
        .any(|value| fuzzy_match(value, search))
}

pub(crate) fn find_first_matching_row_index(
    rows: &[CoreProcessRow],
    search: &str,
    computer_name: &str,
) -> Option<usize> {
    rows.iter()
        .enumerate()
        .filter(|(_, row)| !matches!(row.kind, RowKind::Global))
        .find(|(_, row)| row_matches_search(row, search, computer_name))
        .map(|(index, _)| index)
        .or_else(|| {
            rows.iter()
                .enumerate()
                .find(|(_, row)| row_matches_search(row, search, computer_name))
                .map(|(index, _)| index)
        })
}

pub(crate) fn row_scroll_offset(rows: &[CoreProcessRow], index: usize) -> f32 {
    rows.iter().take(index).map(row_height_px).sum()
}

fn row_height_px(row: &CoreProcessRow) -> f32 {
    if matches!(row.kind, RowKind::Global) {
        36.0
    } else {
        32.0
    }
}

pub(crate) fn groups_to_expand_for_search(
    rows: &[CoreProcessRow],
    search: &str,
    computer_name: &str,
) -> HashSet<String> {
    let mut groups = HashSet::new();
    for row in rows {
        let RowKind::Group {
            process_name,
            pids,
            expanded,
            ..
        } = &row.kind
        else {
            continue;
        };
        if *expanded || pids.len() <= 1 {
            continue;
        }
        if row_matches_search(row, search, computer_name) {
            groups.insert(process_name.to_lowercase());
        }
    }
    groups
}

pub(crate) fn locate_in_rows(
    rows: &[CoreProcessRow],
    search: &str,
    computer_name: &str,
) -> ProcessSearchLocate {
    let search = search.trim();
    if search.is_empty() {
        return ProcessSearchLocate::default();
    }

    let groups_to_expand = groups_to_expand_for_search(rows, search, computer_name);
    if !groups_to_expand.is_empty() {
        return ProcessSearchLocate {
            needs_row_rebuild: true,
            ..ProcessSearchLocate::default()
        };
    }

    let Some(index) = find_first_matching_row_index(rows, search, computer_name) else {
        return ProcessSearchLocate::default();
    };

    ProcessSearchLocate {
        matched_row_index: Some(index),
        scroll_offset_px: row_scroll_offset(rows, index),
        needs_row_rebuild: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flowbrake_core::{GlobalRule, ProcessRule};

    #[test]
    fn fuzzy_match_is_case_insensitive_and_subsequence_based() {
        assert!(fuzzy_match("Google Chrome", "gochr"));
        assert!(fuzzy_match("Google Chrome", "CHROME"));
        assert!(!fuzzy_match("Google Chrome", "xyz"));
    }

    #[test]
    fn find_first_matching_row_index_skips_global_row_when_possible() {
        let rows = vec![
            CoreProcessRow::global(GlobalRule::default()),
            CoreProcessRow {
                kind: RowKind::Group {
                    process_name: "chrome.exe".to_string(),
                    display_name: "Google Chrome".to_string(),
                    exe_path: String::new(),
                    pids: vec![100],
                    expanded: false,
                },
                dl_bps: 0.0,
                ul_bps: 0.0,
                rule: ProcessRule::default(),
            },
        ];

        assert_eq!(find_first_matching_row_index(&rows, "chrome", "PC"), Some(1));
    }

    #[test]
    fn row_scroll_offset_accounts_for_global_row_height() {
        let rows = vec![
            CoreProcessRow::global(GlobalRule::default()),
            CoreProcessRow {
                kind: RowKind::Group {
                    process_name: "chrome.exe".to_string(),
                    display_name: "Google Chrome".to_string(),
                    exe_path: String::new(),
                    pids: vec![100],
                    expanded: false,
                },
                dl_bps: 0.0,
                ul_bps: 0.0,
                rule: ProcessRule::default(),
            },
        ];

        assert_eq!(row_scroll_offset(&rows, 1), 36.0);
    }

    #[test]
    fn locate_in_rows_requests_rebuild_for_collapsed_group_match() {
        let rows = vec![
            CoreProcessRow::global(GlobalRule::default()),
            CoreProcessRow {
                kind: RowKind::Group {
                    process_name: "chrome.exe".to_string(),
                    display_name: "Google Chrome".to_string(),
                    exe_path: String::new(),
                    pids: vec![100, 200],
                    expanded: false,
                },
                dl_bps: 0.0,
                ul_bps: 0.0,
                rule: ProcessRule::default(),
            },
        ];

        let locate = locate_in_rows(&rows, "chrome", "PC");
        assert!(locate.needs_row_rebuild);
        assert_eq!(locate.matched_row_index, None);
    }
}
