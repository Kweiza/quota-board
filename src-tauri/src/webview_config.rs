//! Creates the windows `tauri.conf.json` declares, with macOS's WebKit told to
//! paint in the web content process instead of its GPU process.
//!
//! WebKit's GPU process initialises an audio session for every web process
//! that connects to it — unconditionally, in `GPUConnectionToWebProcess`'s
//! constructor, on its main thread — and that initialisation is a synchronous
//! request to `coreaudiod`. When `coreaudiod` stops answering new clients the
//! GPU process never serves a single paint. Measured twice on a real machine
//! (2026-09-20 and 2026-10-05): the widget window existed, was visible and
//! accepted drags, and showed no pixels, on every relaunch until `coreaudiod`
//! was restarted. A transparent, undecorated window that paints nothing is
//! indistinguishable from an app that did not launch.
//!
//! This app plays no audio, and WebKit has no setting that skips the audio
//! session alone. The only way out is to never connect to the GPU process:
//! with DOM rendering moved back into the web content process, none is spawned.
//!
//! `"create": false` in `tauri.conf.json` is what hands window creation to this
//! module. The configuration has to exist before the `WKWebView` does, and a
//! window Tauri creates from config never offers that moment.

use tauri::{App, WebviewWindowBuilder};

/// Builds every configured window. Called first thing in `setup()`, which is
/// where Tauri itself would have created them a moment earlier.
pub(crate) fn create_windows(app: &App) -> tauri::Result<()> {
    for config in &app.config().app.windows {
        let builder = WebviewWindowBuilder::from_config(app.handle(), config)?;
        // One configuration per window: wry installs each webview's scripts
        // and handlers on the configuration's user content controller.
        #[cfg(target_os = "macos")]
        let builder = match macos::configuration_without_gpu_process() {
            Some(configuration) => builder.with_webview_configuration(configuration),
            None => builder,
        };
        builder.build()?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod macos {
    use objc2::rc::Retained;
    use objc2::runtime::{AnyClass, AnyObject, Bool};
    use objc2::{msg_send, sel, MainThreadMarker};
    use objc2_foundation::{NSArray, NSString};
    use objc2_web_kit::WKWebViewConfiguration;

    /// The one rendering path this widget uses. Canvas, WebGL and media have
    /// GPU-process flags of their own; the frontend uses none of them, and a
    /// flag turned off for no measured reason is a behaviour change with no
    /// test behind it.
    const DOM_RENDERING_IN_GPU_PROCESS: &str = "UseGPUProcessForDOMRenderingEnabled";

    /// A configuration whose webview paints without the GPU process, or `None`
    /// when this WebKit does not offer the switch.
    ///
    /// `_features` and `_setEnabled:forFeature:` are WebKit SPI, so every step
    /// is checked before it is used and a miss falls back to WebKit's default
    /// rather than failing: a widget that renders the old way is strictly
    /// better than one that does not start.
    pub(super) fn configuration_without_gpu_process() -> Option<Retained<WKWebViewConfiguration>> {
        let mtm = MainThreadMarker::new()?;
        let preferences_class = AnyClass::get(c"WKPreferences")?;
        preferences_class.class_method(sel!(_features))?;
        // SAFETY: the selector was just confirmed on the class; it returns an
        // autoreleased NSArray of feature objects.
        let features: Retained<NSArray<AnyObject>> =
            unsafe { msg_send![preferences_class, _features] };
        let feature = features.iter().find(|feature| {
            // SAFETY: every element is a `_WKFeature`, whose `key` is an
            // NSString property.
            let key: Option<Retained<NSString>> = unsafe { msg_send![&**feature, key] };
            key.is_some_and(|key| key.to_string() == DOM_RENDERING_IN_GPU_PROCESS)
        })?;

        // SAFETY: plain construction on the main thread, proven by `mtm`.
        let configuration = unsafe { WKWebViewConfiguration::new(mtm) };
        // SAFETY: `preferences` is public API and never nil.
        let preferences: Retained<AnyObject> = unsafe { msg_send![&configuration, preferences] };
        if !preferences
            .class()
            .responds_to(sel!(_setEnabled:forFeature:))
        {
            return None;
        }
        // SAFETY: the selector was just confirmed; it takes a BOOL and the
        // feature object obtained above.
        let _: () = unsafe {
            msg_send![&preferences, _setEnabled: Bool::NO, forFeature: &*feature]
        };
        Some(configuration)
    }
}
