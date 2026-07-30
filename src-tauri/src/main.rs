#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::Manager;
use tauri_plugin_window_state::StateFlags;

fn main() {
    // Must be set before gtk::init(). .setup() is already too late — the
    // runtime, and therefore GTK, is created inside .build().
    #[cfg(target_os = "linux")]
    {
        std::env::set_var("GDK_BACKEND", "x11");
    }

    tauri::Builder::default()
        .plugin(
            tauri_plugin_window_state::Builder::default()
                // The default is all(), which is harmful for the widget:
                // DECORATIONS would override decorations:false, and VISIBLE
                // would resurrect a window we deliberately start hidden.
                .with_state_flags(StateFlags::POSITION | StateFlags::SIZE)
                .skip_initial_state("settings")
                .build(),
        )
        .setup(|app| {
            // No restore_state() call here on purpose. "settings" is the only
            // label passed to skip_initial_state, so the plugin restores the
            // widget itself before setup() runs. Measured on macOS 15.6 with
            // plugin 2.4.1: widget moved to (300,700), quit, relaunched, and it
            // came back at (300,700) with no explicit restore in this closure.
            if let Some(widget) = app.get_webview_window("widget") {
                widget.show()?;
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the settings window hides it rather than quitting.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "settings" {
                    api.prevent_close();
                    let _ = window.hide();
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("failed to build the Tauri application")
        // No manual save on exit either: plugin 2.4.1 already persists from
        // RunEvent::Exit. Measured — quitting wrote the moved position to
        // ~/Library/Application Support/com.quoata.board/.window-state.json.
        .run(|_app, _event| {
            // The two-argument run() form is kept because later tasks need the
            // run-loop closure (Task 19's tray, macOS Reopen).
        });
}
