use tauri::menu::MenuBuilder;
use tauri::tray::TrayIconBuilder;
use tauri::Manager;

/// Shows the widget if it is hidden, hides it if it is shown.
///
/// Shared by the tray menu and the global shortcut so the two cannot drift into
/// different ideas of what "toggle" means.
///
/// **Deliberately does not touch `AppState::webview_visible`.** §6.3's gate is
/// the window's own `is_visible()`/`is_minimized()` ANDed with what the webview
/// reports, and `poll_loop` re-reads the window signals every five seconds — so
/// hiding from here already closes the gate and showing already reopens it, and
/// both self-heal on the next tick. Pushing a `false` into the webview half
/// instead would create exactly the stale value that half cannot clear on its
/// own (`state.rs`'s note on the pushed signal): polling would stay off after
/// the widget came back until the webview's 30-second heartbeat happened to
/// fire.
///
/// A window whose visibility cannot be read is treated as hidden, so the action
/// is to show it. This is the recovery path — the one thing it must not do is
/// leave a user with no way to get the widget back.
pub fn toggle_widget(app: &tauri::AppHandle) {
    let Some(w) = app.get_webview_window("widget") else {
        return;
    };
    let _ = if w.is_visible().unwrap_or(false) { w.hide() } else { w.show() };
}

/// The tray icon and its menu. docs/design.md §3.3.
///
/// **Every action lives in the menu, and that is not a style choice.** Tauri
/// documents `on_tray_icon_event` as "Linux: Unsupported. The event is not
/// emitted", and `show_menu_on_left_click` is unsupported there too, so a
/// left-click-to-toggle design would simply not exist on Linux — the platform
/// where this menu is the *only* recovery route, because the global shortcut
/// needs X11 and fails outright under pure Wayland.
///
/// **No settings entry**, per §3.3: the widget's gear is the single route into
/// that window, and a second one would be a second thing to keep in step.
///
/// On Linux the icon silently does not appear without
/// `libayatana-appindicator3-1` — already declared in `tauri.conf.json`'s deb
/// dependencies.
pub fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let menu = MenuBuilder::new(app)
        .text("toggle_widget", "Show / hide widget")
        .separator()
        // The only way to quit. The app has no menu bar of its own, the widget
        // is undecorated, and closing the settings window hides it — so without
        // this item the process can only be killed, and a kill skips
        // `RunEvent::Exit`, which is what persists the widget's position.
        .quit_with_text("Quit Quota Board")
        .build()?;

    TrayIconBuilder::with_id("main-tray")
        // **Not `default_window_icon()`.** That is `icons/icon.png`, which is a
        // 512x512 image of one flat colour with no transparency anywhere — a
        // placeholder that renders in the menu bar as exactly what it is, a
        // filled box. This icon is monochrome with a real alpha channel, which
        // is what macOS template rendering needs: it recolours the alpha
        // silhouette to match the menu bar, light or dark.
        .icon(tauri::image::Image::from_bytes(include_bytes!("../icons/tray.png"))?)
        .icon_as_template(true)
        .menu(&menu)
        // macOS and Windows put the menu on a left click, which is what users
        // of those platforms reach for first; measured on macOS, `false` left
        // the icon looking dead to a left click. Unsupported on Linux, where
        // the appindicator opens its menu on either button anyway.
        .show_menu_on_left_click(true)
        .tooltip("Quota Board")
        .on_menu_event(|app, event| {
            if event.id().as_ref() == "toggle_widget" {
                toggle_widget(app);
            }
        })
        .build(app)?;
    Ok(())
}
