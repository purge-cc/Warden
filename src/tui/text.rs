use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

pub(crate) fn width(value: &str) -> usize {
    UnicodeWidthStr::width(value)
}

pub(crate) fn fit(value: &str, cells: usize) -> String {
    truncate(value, cells, false)
}

pub(crate) fn fit_tail(value: &str, cells: usize) -> String {
    truncate(value, cells, true)
}

pub(crate) fn pad(value: &str, cells: usize) -> String {
    let value = fit(value, cells);
    let padding = cells.saturating_sub(width(&value));
    format!("{value}{}", " ".repeat(padding))
}

/// Wrap without splitting graphemes; prefer the last whitespace in each row.
pub(crate) fn wrap(value: &str, cells: usize) -> Vec<String> {
    if cells == 0 {
        return Vec::new();
    }
    let mut rows = Vec::new();
    for line in value.split('\n') {
        if line.is_empty() {
            rows.push(String::new());
            continue;
        }
        let mut remaining = line;
        while !remaining.is_empty() {
            let mut used = 0;
            let mut end = 0;
            let mut space = None;
            for (offset, grapheme) in remaining.grapheme_indices(true) {
                let next = width(grapheme);
                if used + next > cells {
                    break;
                }
                used += next;
                end = offset + grapheme.len();
                if grapheme.chars().all(char::is_whitespace) {
                    space = Some(end);
                }
            }
            if end == remaining.len() {
                rows.push(remaining.to_owned());
                break;
            }
            if end == 0 {
                let grapheme = remaining.graphemes(true).next().unwrap();
                rows.push(fit(grapheme, cells));
                remaining = &remaining[grapheme.len()..];
            } else {
                let cut = space.unwrap_or(end);
                rows.push(remaining[..cut].trim_end().to_owned());
                remaining = &remaining[cut..];
            }
        }
    }
    rows
}

fn truncate(value: &str, cells: usize, tail: bool) -> String {
    if width(value) <= cells {
        return value.to_owned();
    }
    if cells == 0 {
        return String::new();
    }
    let mut used = 1;
    if tail {
        let mut start = value.len();
        for (offset, grapheme) in value.grapheme_indices(true).rev() {
            let next = width(grapheme);
            if used + next > cells {
                break;
            }
            used += next;
            start = offset;
        }
        format!("…{}", &value[start..])
    } else {
        let mut end = 0;
        for (offset, grapheme) in value.grapheme_indices(true) {
            let next = width(grapheme);
            if used + next > cells {
                break;
            }
            used += next;
            end = offset + grapheme.len();
        }
        format!("{}…", &value[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn graphemes_survive_clipping_and_padding() {
        assert_eq!(fit("e\u{301}cole", 3), "e\u{301}c…");
        assert_eq!(fit("端末-device", 4), "端…");
        assert_eq!(fit_tail("device-端末", 4), "…末");
        assert_eq!(width(&pad("端末", 7)), 7);
        for sample in ["e\u{301}cole", "端末", "👩‍💻 laptop", "192.0.2.100"] {
            for cells in 0..20 {
                assert!(width(&fit(sample, cells)) <= cells);
                assert!(width(&fit_tail(sample, cells)) <= cells);
            }
        }
    }

    #[test]
    fn wrapped_rows_stay_within_cell_budget() {
        for cells in 1..20 {
            for row in wrap("端末 e\u{301}cole 👩‍💻 laptop\nsecond line", cells) {
                assert!(width(&row) <= cells, "{cells}: {row}");
            }
        }
        assert_eq!(wrap("hello world", 6), vec!["hello", "world"]);
    }
}
