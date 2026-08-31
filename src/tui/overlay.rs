//! Shared layout helpers for popup overlays.
//!
//! Every TUI overlay (help, scope modal, welcome banner, devices form,
//! lists assignment modal) needs to centre a fixed-size popup inside a
//! parent rect with overflow clamping. Before this module each call site
//! carried its own copy with subtly different parameter orders and
//! spelling, which had already drifted at the API level.

use ratatui::layout::Rect;

/// Compute a popup `Rect` of `width` × `height` centred inside `parent`.
/// Clamps so the popup never overflows the parent on a small terminal.
pub fn centered_rect(parent: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(parent.width);
    let h = height.min(parent.height);
    let x = parent.x + parent.width.saturating_sub(w) / 2;
    let y = parent.y + parent.height.saturating_sub(h) / 2;
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn centered_within_parent() {
        let parent = Rect {
            x: 0,
            y: 0,
            width: 100,
            height: 50,
        };
        let r = centered_rect(parent, 60, 22);
        assert_eq!(r.width, 60);
        assert_eq!(r.height, 22);
        assert_eq!(r.x, 20); // (100 - 60) / 2
        assert_eq!(r.y, 14); // (50 - 22) / 2
    }

    #[test]
    fn clamps_when_parent_smaller_than_popup() {
        let parent = Rect {
            x: 0,
            y: 0,
            width: 30,
            height: 10,
        };
        let r = centered_rect(parent, 60, 22);
        assert_eq!(r.width, 30);
        assert_eq!(r.height, 10);
        assert_eq!(r.x, 0);
        assert_eq!(r.y, 0);
    }

    #[test]
    fn respects_parent_origin_offset() {
        // Parent does not start at (0,0) — popup must offset accordingly
        // so `f.area()` slices that don't begin at origin still centre.
        let parent = Rect {
            x: 10,
            y: 5,
            width: 80,
            height: 24,
        };
        let r = centered_rect(parent, 40, 10);
        assert_eq!(r.x, 10 + (80 - 40) / 2);
        assert_eq!(r.y, 5 + (24 - 10) / 2);
    }
}
