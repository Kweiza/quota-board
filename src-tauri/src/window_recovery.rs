use tauri::{Monitor, PhysicalPosition, Runtime, WebviewWindow};

const EDGE_MARGIN: i32 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Point {
    x: i32,
    y: i32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Size {
    width: u32,
    height: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rect {
    x: i32,
    y: i32,
    width: u32,
    height: u32,
}

/// Moves and shows the widget on the primary display.
///
/// This is deliberately unconditional. A monitor can disappear while the app
/// is running, and platform geometry APIs can still call the old position
/// "visible" during that transition. The tray action is the user's escape
/// hatch when the automatic window-state restore cannot recover it.
pub(crate) fn move_widget_to_primary<R: Runtime>(window: &WebviewWindow<R>) -> tauri::Result<()> {
    let position_result = (|| -> tauri::Result<()> {
        let destination = match window.primary_monitor()? {
            Some(primary) => Some(visible_area(&primary)),
            None => window.available_monitors()?.first().map(visible_area),
        };

        if let Some(destination) = destination {
            let position = destination.top_right_position(size(window.outer_size()?));
            window.set_position(PhysicalPosition::new(position.x, position.y))?;
        }
        Ok(())
    })();
    let _ = window.unminimize();
    // Showing is an independent recovery. On Wayland `set_position` can be
    // unsupported, and returning before `show` would make the escape hatch
    // strictly worse than the existing toggle on exactly that platform.
    let show_result = window.show();
    position_result.and(show_result)
}

fn visible_area(monitor: &Monitor) -> Rect {
    let work_area = monitor.work_area();
    Rect {
        x: work_area.position.x,
        y: work_area.position.y,
        width: work_area.size.width,
        height: work_area.size.height,
    }
}

fn size(size: tauri::PhysicalSize<u32>) -> Size {
    Size {
        width: size.width,
        height: size.height,
    }
}

impl Rect {
    fn top_right_position(self, window_size: Size) -> Point {
        let horizontal_room = i64::from(self.width) - i64::from(window_size.width);
        let x_offset = if horizontal_room >= i64::from(EDGE_MARGIN * 2) {
            horizontal_room - i64::from(EDGE_MARGIN)
        } else {
            0
        };
        let y_offset = if self.height >= window_size.height.saturating_add(EDGE_MARGIN as u32 * 2) {
            EDGE_MARGIN
        } else {
            0
        };

        Point {
            x: saturating_i32(i64::from(self.x) + x_offset),
            y: self.y.saturating_add(y_offset),
        }
    }
}

fn saturating_i32(value: i64) -> i32 {
    value.clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_widget_starts_centered_on_the_primary_display_before_state_restore() {
        let config: serde_json::Value =
            serde_json::from_str(include_str!("../tauri.conf.json")).unwrap();
        let widget = config["app"]["windows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|window| window["label"] == "widget")
            .unwrap();

        assert_eq!(widget["center"], true);
        assert_eq!(widget["visible"], false);
    }

    #[test]
    fn tray_recovery_places_the_widget_inside_the_primary_work_area() {
        let primary = Rect {
            x: 0,
            y: 0,
            width: 1728,
            height: 1084,
        };

        assert_eq!(
            primary.top_right_position(Size {
                width: 280,
                height: 365,
            }),
            Point { x: 1432, y: 16 }
        );
    }

    #[test]
    fn tray_recovery_handles_a_primary_display_with_negative_coordinates() {
        let primary = Rect {
            x: -3068,
            y: -1440,
            width: 2560,
            height: 1440,
        };

        assert_eq!(
            primary.top_right_position(Size {
                width: 280,
                height: 365,
            }),
            Point { x: -804, y: -1424 }
        );
    }

    #[test]
    fn a_widget_larger_than_the_work_area_uses_its_origin_without_overflow() {
        let primary = Rect {
            x: i32::MAX - 100,
            y: i32::MAX - 100,
            width: 50,
            height: 50,
        };

        assert_eq!(
            primary.top_right_position(Size {
                width: u32::MAX,
                height: u32::MAX,
            }),
            Point {
                x: i32::MAX - 100,
                y: i32::MAX - 100,
            }
        );
    }
}
