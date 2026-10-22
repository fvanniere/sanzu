//! Native Wayland client (prototype)
//!
//! Seamless mode keeps the X11 design: one fullscreen surface covers the
//! output. Outside the remote windows its pixels are transparent and its input
//! region is empty, so local windows below get the clicks.
//!
//! The decoded frame goes as is into a shared memory buffer; wp_viewporter
//! scales it to the surface, which handles both `--zoom` and fractional
//! output scales without CPU work.

use crate::{
    client_utils::{Area, Client},
    client_x11::{select_monitor, Monitor},
    utils::{ClientArgsConfig, ClipboardConfig},
};
use anyhow::{Context, Result};
use sanzu_common::tunnel;

use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    os::fd::OwnedFd,
    sync::mpsc::{channel, Receiver, Sender},
    thread,
};

use smithay_client_toolkit::{
    compositor::{CompositorHandler, CompositorState, Region},
    data_device_manager::{
        data_device::{DataDevice, DataDeviceHandler},
        data_offer::{DataOfferHandler, DragOffer},
        data_source::{CopyPasteSource, DataSourceHandler},
        DataDeviceManagerState, WritePipe,
    },
    delegate_compositor, delegate_data_device, delegate_output, delegate_pointer,
    delegate_registry, delegate_seat, delegate_shm, delegate_xdg_shell, delegate_xdg_window,
    output::{OutputHandler, OutputState},
    registry::{ProvidesRegistryState, RegistryState},
    registry_handlers,
    seat::{
        pointer::{PointerEvent, PointerEventKind, PointerHandler},
        Capability, SeatHandler, SeatState,
    },
    shell::{
        xdg::{
            window::{Window, WindowConfigure, WindowDecorations, WindowHandler},
            XdgShell,
        },
        WaylandSurface,
    },
    shm::{
        slot::{Buffer, SlotPool},
        Shm, ShmHandler,
    },
};
use wayland_client::{
    delegate_noop,
    globals::{registry_queue_init, GlobalList},
    protocol::{
        wl_data_device::WlDataDevice,
        wl_data_device_manager::DndAction,
        wl_data_source::WlDataSource,
        wl_keyboard::{self, WlKeyboard},
        wl_output::{self, WlOutput},
        wl_pointer::WlPointer,
        wl_seat::WlSeat,
        wl_shm, wl_surface,
    },
    Connection, Dispatch, EventQueue, QueueHandle, WEnum,
};
use wayland_protocols::wp::{
    fractional_scale::v1::client::{
        wp_fractional_scale_manager_v1::WpFractionalScaleManagerV1,
        wp_fractional_scale_v1::{self, WpFractionalScaleV1},
    },
    keyboard_shortcuts_inhibit::zv1::client::{
        zwp_keyboard_shortcuts_inhibit_manager_v1::ZwpKeyboardShortcutsInhibitManagerV1,
        zwp_keyboard_shortcuts_inhibitor_v1::ZwpKeyboardShortcutsInhibitorV1,
    },
    viewporter::client::{wp_viewport::WpViewport, wp_viewporter::WpViewporter},
};

/// Same X11 keycodes as the X11 client: Wayland sends evdev codes, which are
/// the X11 keycodes minus 8
const EVDEV_TO_X11: u32 = 8;
const KEY_CTRL: usize = 37;
const KEY_SHIFT: usize = 50;
const KEY_ALT: usize = 64;
const KEY_S: u32 = 39;
const KEY_C: u32 = 54;
const KEY_H: u32 = 43;
const KEY_N: u32 = 57;

/// Linux input button codes and their X11 button numbers
const BUTTONS: [(u32, u32); 5] = [
    (0x110, 1), // BTN_LEFT
    (0x112, 2), // BTN_MIDDLE
    (0x111, 3), // BTN_RIGHT
    (0x113, 8), // BTN_SIDE
    (0x114, 9), // BTN_EXTRA
];

/// Pixels of continuous scrolling (touchpads) worth one wheel step
const SCROLL_STEP: f64 = 10.0;

/// xkb modifier masks of the standard keymaps
const MOD_LOCK: u32 = 1 << 1;
const MOD_NUM: u32 = 1 << 4;

const APP_ID: &str = "sanzu_client";

const TEXT_MIME_TYPES: [&str; 4] = [
    "text/plain;charset=utf-8",
    "UTF8_STRING",
    "text/plain",
    "STRING",
];

/// Zero pixels outside `rects`, make them opaque inside
///
/// The buffer is premultiplied ARGB8888: a transparent pixel must be zeroed
/// entirely, not only its alpha, or the compositor adds its color.
fn apply_seamless_mask(canvas: &mut [u8], width: usize, height: usize, rects: &[Rect]) {
    let mut spans = vec![];
    for (y, row) in canvas.chunks_exact_mut(width * 4).take(height).enumerate() {
        spans.clear();
        for rect in rects {
            if (rect.y..rect.y + rect.height).contains(&y) {
                spans.push((rect.x.min(width), (rect.x + rect.width).min(width)));
            }
        }
        spans.sort_unstable();
        let mut x = 0;
        for &(start, end) in spans.iter() {
            if start > x {
                row[x * 4..start * 4].fill(0);
            }
            for pixel in row[start.max(x) * 4..end.max(x) * 4].chunks_exact_mut(4) {
                pixel[3] = 0xFF;
            }
            x = x.max(end);
        }
        row[x * 4..].fill(0);
    }
}

/// A rectangle in buffer pixels
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Rect {
    x: usize,
    y: usize,
    width: usize,
    height: usize,
}

/// Convert remote areas, in client size units, to `target` units
fn areas_to_rects(
    areas: &[(usize, Area)],
    from: (u16, u16),
    target: (u32, u32),
) -> Vec<(i32, i32, i32, i32)> {
    let scale = |value: i32, from: u16, to: u32| -> i32 {
        ((value as i64 * to as i64) / from.max(1) as i64) as i32
    };
    areas
        .iter()
        .filter(|(_, area)| area.mapped)
        .map(|(_, area)| {
            let x0 = scale(area.position.0 as i32, from.0, target.0);
            let y0 = scale(area.position.1 as i32, from.1, target.1);
            let x1 = scale(
                area.position.0 as i32 + area.size.0 as i32,
                from.0,
                target.0,
            );
            let y1 = scale(
                area.position.1 as i32 + area.size.1 as i32,
                from.1,
                target.1,
            );
            (x0, y0, x1 - x0, y1 - y0)
        })
        .collect()
}

/// Wayland objects and the state their events update
pub struct WaylandState {
    registry_state: RegistryState,
    output_state: OutputState,
    seat_state: SeatState,
    compositor: CompositorState,
    shm: Shm,
    pool: SlotPool,
    window: Window,
    viewport: WpViewport,
    fractional_scale: Option<WpFractionalScaleV1>,
    inhibit_manager: Option<ZwpKeyboardShortcutsInhibitManagerV1>,
    inhibitor: Option<ZwpKeyboardShortcutsInhibitorV1>,
    data_device_manager: Option<DataDeviceManagerState>,
    data_device: Option<DataDevice>,
    seat: Option<WlSeat>,
    keyboard: Option<WlKeyboard>,
    pointer: Option<WlPointer>,

    /// Window size in surface (logical) coordinates
    logical_size: (u32, u32),
    /// Output scale, 1.5 for 150%
    scale: f64,
    configured: bool,
    closed: bool,
    fullscreen: bool,
    /// Output holding the surface
    current_output: Option<WlOutput>,

    /// Frame buffer, at the decoded frame size
    buffer: Option<Buffer>,
    /// Cursor image and hotspot sent by the server
    cursor_surface: wl_surface::WlSurface,
    cursor_buffer: Option<Buffer>,
    cursor_hot: (i32, i32),
    /// Serial of the last pointer enter, needed to set the cursor
    pointer_serial: Option<u32>,
    /// Serial of the last input event, needed to set the selection
    input_serial: u32,
    scroll_accumulator: (f64, f64),

    /// Pending messages to the server
    events: Vec<tunnel::MessageClient>,
    last_move: Option<tunnel::MessageClient>,
    keys_state: Vec<bool>,
    need_update: bool,
    resized: bool,
    /// A decoded frame waits in the buffer, not attached yet
    frame_ready: bool,
    display_stats: bool,
    clipboard_trig: bool,
    grab_keyboard: bool,
    locked_modifiers: u32,
    sync_key_locks_needed: bool,

    clipboard_source: Option<(CopyPasteSource, String)>,
    clipboard_sender: Sender<String>,
}

/// Holds information on the local Wayland client
pub struct ClientWayland {
    conn: Connection,
    event_queue: EventQueue<WaylandState>,
    state: WaylandState,
    seamless: bool,
    /// Areas of the last shaped frame, sorted
    areas: Vec<(usize, Area)>,
    /// Size of the last decoded (remote) frame stored in the buffer
    frame_size: (u32, u32),
    sync_key_locks: bool,
    clipboard_config: ClipboardConfig,
    clipboard_event_receiver: Receiver<String>,
    clipboard_last_value: Option<String>,
}

fn bind_optional<I, State>(globals: &GlobalList, qh: &QueueHandle<State>) -> Option<I>
where
    I: wayland_client::Proxy + 'static,
    State: Dispatch<I, ()> + 'static,
{
    match globals.bind(qh, 1..=1, ()) {
        Ok(global) => Some(global),
        Err(err) => {
            info!("Wayland {} unavailable: {}", I::interface().name, err);
            None
        }
    }
}

impl WaylandState {
    /// Size the client reports to the server: the surface in output pixels
    fn physical_size(&self) -> (u16, u16) {
        let scale = |value: u32| ((value as f64 * self.scale).round() as u32).clamp(1, 0xFFFF);
        (
            scale(self.logical_size.0) as u16,
            scale(self.logical_size.1) as u16,
        )
    }

    /// Outputs in compositor order, with what --monitor matches on
    fn monitors(&self) -> Vec<(WlOutput, Monitor)> {
        self.output_state
            .outputs()
            .filter_map(|output| {
                let info = self.output_state.info(&output)?;
                let position = info.logical_position.unwrap_or(info.location);
                let size = info.logical_size.unwrap_or_default();
                let monitor = Monitor {
                    name: info.name.unwrap_or_default(),
                    primary: false,
                    position: (position.0 as i16, position.1 as i16),
                    size: (size.0 as u16, size.1 as u16),
                };
                Some((output, monitor))
            })
            .collect()
    }

    /// Use the first seat for input and clipboard
    fn adopt_seat(&mut self, qh: &QueueHandle<Self>, seat: &WlSeat) {
        if self.seat.is_none() {
            self.data_device = self
                .data_device_manager
                .as_ref()
                .map(|manager| manager.get_data_device(qh, seat));
            self.seat = Some(seat.clone());
        }
    }

    fn set_scale(&mut self, scale: f64) {
        if scale > 0.0 && scale != self.scale {
            info!("Output scale {}", scale);
            self.scale = scale;
            self.resized = true;
            self.need_update = true;
        }
    }

    fn update_cursor(&self) {
        if let (Some(pointer), Some(serial), Some(_)) =
            (&self.pointer, self.pointer_serial, &self.cursor_buffer)
        {
            pointer.set_cursor(
                serial,
                Some(&self.cursor_surface),
                self.cursor_hot.0,
                self.cursor_hot.1,
            );
        }
    }

    fn set_inhibitor(&mut self, qh: &QueueHandle<Self>, enabled: bool) {
        if !enabled {
            if let Some(inhibitor) = self.inhibitor.take() {
                inhibitor.destroy();
            }
            return;
        }
        if let (None, Some(manager), Some(seat)) =
            (&self.inhibitor, &self.inhibit_manager, &self.seat)
        {
            self.inhibitor =
                Some(manager.inhibit_shortcuts(self.window.wl_surface(), seat, qh, ()));
        }
    }

    /// On focus loss, release the keys still pressed on the server
    fn release_keys(&mut self) {
        for (index, key_state) in self.keys_state.iter_mut().enumerate() {
            if *key_state {
                *key_state = false;
                self.events.push(tunnel::MessageClient {
                    msg: Some(tunnel::message_client::Msg::Key(tunnel::EventKey {
                        keycode: index as u32,
                        updown: false,
                    })),
                });
            }
        }
    }

    fn move_to_next_monitor(&mut self) {
        if !self.fullscreen {
            info!("Wayland lets only the compositor move a window");
            return;
        }
        let outputs: Vec<WlOutput> = self.output_state.outputs().collect();
        if outputs.len() < 2 {
            info!("Single monitor, nothing to move to");
            return;
        }
        let current = self
            .current_output
            .as_ref()
            .and_then(|current| outputs.iter().position(|output| output == current))
            .unwrap_or(0);
        let target = &outputs[(current + 1) % outputs.len()];
        info!("Move to output {:?}", self.output_state.info(target));
        self.window.set_fullscreen(Some(target));
    }

    fn handle_shortcuts(&mut self, qh: &QueueHandle<Self>, keycode: u32) {
        if !(self.keys_state[KEY_CTRL] && self.keys_state[KEY_SHIFT] && self.keys_state[KEY_ALT]) {
            return;
        }
        match keycode {
            KEY_S => {
                self.display_stats = !self.display_stats;
                info!("Toggle server logs");
            }
            KEY_C => self.clipboard_trig = true,
            KEY_H => {
                self.grab_keyboard = !self.grab_keyboard;
                if !self.grab_keyboard {
                    self.release_keys();
                }
                self.set_inhibitor(qh, self.grab_keyboard);
                info!("Toggle grab keyboard {}", self.grab_keyboard);
            }
            KEY_N => self.move_to_next_monitor(),
            _ => {}
        }
    }

    fn button_event(&mut self, position: (f64, f64), button: u32, updown: bool) {
        let (x, y) = self.to_client(position);
        self.events.push(tunnel::MessageClient {
            msg: Some(tunnel::message_client::Msg::Button(tunnel::EventButton {
                x,
                y,
                button,
                updown,
            })),
        });
    }

    /// Surface coordinates to client size units
    fn to_client(&self, position: (f64, f64)) -> (u32, u32) {
        let size = self.physical_size();
        let scale = |value: f64, logical: u32, physical: u16| -> u32 {
            ((value * physical as f64 / logical.max(1) as f64).max(0.0) as u32)
                .min(physical as u32 - 1)
        };
        (
            scale(position.0, self.logical_size.0, size.0),
            scale(position.1, self.logical_size.1, size.1),
        )
    }

    /// Send whole wheel steps as X11 buttons 4/5 (vertical) and 6/7
    fn scroll(&mut self, position: (f64, f64), steps: i32, buttons: (u32, u32)) {
        let button = if steps < 0 { buttons.0 } else { buttons.1 };
        for _ in 0..steps.abs() {
            self.button_event(position, button, true);
            self.button_event(position, button, false);
        }
    }
}

/// Initialize the Wayland client window
pub fn init_wayland(
    arguments: &ClientArgsConfig,
    seamless: bool,
    server_size: Option<(u16, u16)>,
) -> Result<Box<dyn Client>> {
    let conn = Connection::connect_to_env().context("Failed to connect to the Wayland server")?;
    let (globals, mut event_queue) =
        registry_queue_init(&conn).context("Error in registry_queue_init")?;
    let qh = event_queue.handle();

    let compositor = CompositorState::bind(&globals, &qh).context("wl_compositor is needed")?;
    let xdg_shell = XdgShell::bind(&globals, &qh).context("xdg_wm_base is needed")?;
    let shm = Shm::bind(&globals, &qh).context("wl_shm is needed")?;
    let viewporter: WpViewporter = globals
        .bind(&qh, 1..=1, ())
        .context("wp_viewporter is needed")?;
    let fractional_manager: Option<WpFractionalScaleManagerV1> = bind_optional(&globals, &qh);
    let inhibit_manager: Option<ZwpKeyboardShortcutsInhibitManagerV1> =
        bind_optional(&globals, &qh);

    let clipboard_config = match arguments.clipboard.as_str() {
        "allow" => ClipboardConfig::Allow,
        "deny" => ClipboardConfig::Deny,
        "trig" => ClipboardConfig::Trig,
        _ => {
            return Err(anyhow!("Unknown clipboard config: {}", arguments.clipboard));
        }
    };
    let data_device_manager = match clipboard_config {
        ClipboardConfig::Deny => None,
        _ => match DataDeviceManagerState::bind(&globals, &qh) {
            Ok(manager) => Some(manager),
            Err(err) => {
                warn!("No Wayland clipboard: {}", err);
                None
            }
        },
    };

    let surface = compositor.create_surface(&qh);
    let viewport = viewporter.get_viewport(&surface, &qh, ());
    let fractional_scale = fractional_manager
        .as_ref()
        .map(|manager| manager.get_fractional_scale(&surface, &qh, ()));
    let window = xdg_shell.create_window(surface, WindowDecorations::RequestServer, &qh);
    window.set_title(arguments.title.clone());
    window.set_app_id(APP_ID);
    let cursor_surface = compositor.create_surface(&qh);

    let (clipboard_sender, clipboard_event_receiver) = channel();
    let mut state = WaylandState {
        registry_state: RegistryState::new(&globals),
        output_state: OutputState::new(&globals, &qh),
        seat_state: SeatState::new(&globals, &qh),
        compositor,
        pool: SlotPool::new(4 * 1920 * 1080, &shm).context("Cannot create shm pool")?,
        shm,
        window,
        viewport,
        fractional_scale,
        inhibit_manager,
        inhibitor: None,
        data_device_manager,
        data_device: None,
        seat: None,
        keyboard: None,
        pointer: None,
        logical_size: (0, 0),
        scale: 1.0,
        configured: false,
        closed: false,
        fullscreen: !arguments.window_mode,
        current_output: None,
        buffer: None,
        cursor_surface,
        cursor_buffer: None,
        cursor_hot: (0, 0),
        pointer_serial: None,
        input_serial: 0,
        scroll_accumulator: (0.0, 0.0),
        events: vec![],
        last_move: None,
        keys_state: vec![false; 0x100],
        need_update: true,
        resized: false,
        frame_ready: false,
        display_stats: false,
        clipboard_trig: false,
        grab_keyboard: arguments.grab_keyboard,
        locked_modifiers: 0,
        sync_key_locks_needed: arguments.sync_key_locks,
        clipboard_source: None,
        clipboard_sender,
    };

    // Outputs and seats
    event_queue
        .roundtrip(&mut state)
        .context("Error in Wayland roundtrip")?;

    let monitors = state.monitors();
    let output = match &arguments.monitor {
        Some(selector) => {
            let list: Vec<Monitor> = monitors
                .iter()
                .map(|(_, monitor)| monitor.clone())
                .collect();
            let monitor = select_monitor(&list, selector)?;
            info!("Open on output {:?}", monitor);
            monitors
                .iter()
                .find(|(_, candidate)| candidate.name == monitor.name)
                .map(|(output, _)| output.clone())
        }
        None => None,
    };
    // Output pixels per surface unit, until the compositor tells the
    // preferred scale
    let first_output = output
        .clone()
        .or_else(|| monitors.first().map(|(output, _)| output.clone()));
    let output_info = first_output
        .as_ref()
        .and_then(|output| state.output_state.info(output));
    if let Some(info) = &output_info {
        let mode = info.modes.iter().find(|mode| mode.current);
        if let (Some(mode), Some(logical)) = (mode, info.logical_size) {
            if logical.0 > 0 {
                state.scale = mode.dimensions.0 as f64 / logical.0 as f64;
            }
        }
    }

    if state.fullscreen {
        state.window.set_fullscreen(output.as_ref());
    }
    state.window.commit();
    while !state.configured {
        event_queue
            .blocking_dispatch(&mut state)
            .context("Error in Wayland dispatch")?;
    }
    if state.logical_size == (0, 0) {
        // Window mode: the compositor lets us choose
        let size = match (server_size, output_info.and_then(|info| info.logical_size)) {
            (Some((width, height)), _) => (
                (width as f64 / state.scale) as u32,
                (height as f64 / state.scale) as u32,
            ),
            (None, Some((width, height))) => (width as u32, height as u32),
            (None, None) => (1280, 720),
        };
        state.logical_size = size;
    }
    state
        .viewport
        .set_destination(state.logical_size.0 as i32, state.logical_size.1 as i32);
    // Seamless starts fully transparent to the input
    if seamless {
        let region = Region::new(&state.compositor).context("Cannot create region")?;
        state
            .window
            .wl_surface()
            .set_input_region(Some(region.wl_region()));
    }
    state.resized = false;
    if state.grab_keyboard {
        state.set_inhibitor(&qh, true);
    }

    let frame_size = {
        let size = state.physical_size();
        (size.0 as u32, size.1 as u32)
    };
    info!(
        "Wayland window {:?} (scale {}), seamless {}",
        state.logical_size, state.scale, seamless
    );

    Ok(Box::new(ClientWayland {
        conn,
        event_queue,
        state,
        seamless,
        areas: vec![],
        frame_size,
        sync_key_locks: arguments.sync_key_locks,
        clipboard_config,
        clipboard_event_receiver,
        clipboard_last_value: None,
    }))
}

impl ClientWayland {
    fn format(&self) -> wl_shm::Format {
        if self.seamless {
            wl_shm::Format::Argb8888
        } else {
            wl_shm::Format::Xrgb8888
        }
    }

    /// Get a free buffer of the frame size
    fn frame_canvas(&mut self) -> Result<&mut [u8]> {
        let (width, height) = (self.frame_size.0 as i32, self.frame_size.1 as i32);
        let format = self.format();
        let WaylandState { buffer, pool, .. } = &mut self.state;
        let free = match buffer {
            Some(buffer) if buffer.height() == height && buffer.stride() == width * 4 => {
                buffer.canvas(pool).is_some()
            }
            _ => false,
        };
        if !free {
            // The compositor still reads the previous one: double buffering
            let (new_buffer, _) = pool
                .create_buffer(width, height, width * 4, format)
                .context("Cannot create frame buffer")?;
            *buffer = Some(new_buffer);
        }
        buffer
            .as_ref()
            .context("No frame buffer")?
            .canvas(pool)
            .context("Frame buffer is busy")
    }

    fn set_input_region(&self) -> Result<()> {
        let region = Region::new(&self.state.compositor).context("Cannot create region")?;
        let size = self.state.physical_size();
        for (x, y, width, height) in areas_to_rects(&self.areas, size, self.state.logical_size) {
            region.add(x, y, width, height);
        }
        self.state
            .window
            .wl_surface()
            .set_input_region(Some(region.wl_region()));
        Ok(())
    }
}

impl Client for ClientWayland {
    fn size(&self) -> (u16, u16) {
        self.state.physical_size()
    }

    fn set_cursor(&mut self, cursor_data: &[u8], size: (u32, u32), hot: (u16, u16)) -> Result<()> {
        let (width, height) = (size.0 as i32, size.1 as i32);
        let (buffer, canvas) = self
            .state
            .pool
            .create_buffer(width, height, width * 4, wl_shm::Format::Argb8888)
            .context("Cannot create cursor buffer")?;
        let len = canvas.len().min(cursor_data.len());
        canvas[..len].copy_from_slice(&cursor_data[..len]);
        buffer
            .attach_to(&self.state.cursor_surface)
            .context("Cannot attach cursor buffer")?;
        self.state.cursor_surface.damage_buffer(0, 0, width, height);
        self.state.cursor_surface.commit();
        self.state.cursor_buffer = Some(buffer);
        self.state.cursor_hot = (hot.0 as i32, hot.1 as i32);
        self.state.update_cursor();
        self.conn.flush().context("Error in Wayland flush")?;
        Ok(())
    }

    fn set_img(&mut self, img: &[u8], size: (u32, u32)) -> Result<()> {
        self.frame_size = size;
        let canvas = self.frame_canvas()?;
        let len = canvas.len().min(img.len());
        canvas[..len].copy_from_slice(&img[..len]);
        self.state.frame_ready = true;
        self.state.need_update = true;
        Ok(())
    }

    fn update(&mut self, areas: &HashMap<usize, Area>) -> Result<()> {
        if !self.state.need_update {
            return Ok(());
        }
        if self.seamless {
            let mut distant_areas: Vec<(usize, Area)> =
                areas.iter().map(|(a, b)| (*a, b.clone())).collect();
            distant_areas.sort();
            if distant_areas != self.areas {
                for area in distant_areas.iter() {
                    trace!("    {:?}", area);
                }
                self.areas = distant_areas;
                self.set_input_region()?;
            }
        }

        let surface = self.state.window.wl_surface().clone();
        if self.state.frame_ready {
            let (width, height) = (self.frame_size.0 as usize, self.frame_size.1 as usize);
            let buffer = self.state.buffer.as_ref().context("No frame buffer")?;
            if self.seamless {
                let size = self.state.physical_size();
                let rects: Vec<Rect> = areas_to_rects(&self.areas, size, self.frame_size)
                    .into_iter()
                    .map(|(x, y, w, h)| {
                        let (x0, y0) = (x.max(0) as usize, y.max(0) as usize);
                        let (x1, y1) = ((x + w).max(0) as usize, (y + h).max(0) as usize);
                        Rect {
                            x: x0,
                            y: y0,
                            width: x1.saturating_sub(x0),
                            height: y1.saturating_sub(y0),
                        }
                    })
                    .collect();
                // set_img filled this buffer and nothing attached it since
                let canvas = buffer
                    .canvas(&mut self.state.pool)
                    .context("Frame buffer is busy")?;
                apply_seamless_mask(canvas, width, height, &rects);
            }
            buffer
                .attach_to(&surface)
                .context("Cannot attach frame buffer")?;
            surface.damage_buffer(0, 0, width as i32, height as i32);
            self.state.frame_ready = false;
        }
        self.state.viewport.set_destination(
            self.state.logical_size.0 as i32,
            self.state.logical_size.1 as i32,
        );
        surface.commit();
        self.state.need_update = false;
        self.conn.flush().context("Error in Wayland flush")?;
        Ok(())
    }

    fn set_clipboard(&mut self, data: &str) -> Result<()> {
        let state = &mut self.state;
        if let (Some(manager), Some(device)) = (&state.data_device_manager, &state.data_device) {
            let qh = self.event_queue.handle();
            let source = manager.create_copy_paste_source(&qh, TEXT_MIME_TYPES);
            source.set_selection(device, state.input_serial);
            state.clipboard_source = Some((source, data.to_owned()));
            self.conn.flush().context("Error in Wayland flush")?;
        }
        Ok(())
    }

    fn poll_events(&mut self) -> Result<tunnel::MessagesClient> {
        self.event_queue.flush().context("Error in Wayland flush")?;
        if let Some(guard) = self.event_queue.prepare_read() {
            match guard.read() {
                Ok(_) => {}
                Err(wayland_client::backend::WaylandError::Io(err))
                    if err.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(err) => return Err(err).context("Error in Wayland read"),
            }
        }
        self.event_queue
            .dispatch_pending(&mut self.state)
            .context("Error in Wayland dispatch")?;

        if self.state.closed {
            return Err(anyhow!("Window closed"));
        }

        let state = &mut self.state;
        let mut events = std::mem::take(&mut state.events);

        if self.sync_key_locks && state.sync_key_locks_needed {
            events.push(tunnel::MessageClient {
                msg: Some(tunnel::message_client::Msg::Keylocks(
                    tunnel::EventKeyLocks {
                        caps_lock: state.locked_modifiers & MOD_LOCK != 0,
                        num_lock: state.locked_modifiers & MOD_NUM != 0,
                        // Not a modifier in the standard keymaps
                        scroll_lock: false,
                    },
                )),
            });
            state.sync_key_locks_needed = false;
        }

        events.extend(state.last_move.take());

        if state.resized {
            state.resized = false;
            let (width, height) = state.physical_size();
            info!("Resize {}x{}", width, height);
            events.push(tunnel::MessageClient {
                msg: Some(tunnel::message_client::Msg::Display(tunnel::EventDisplay {
                    width: width as u32,
                    height: height as u32,
                })),
            });
        }

        while let Ok(data) = self.clipboard_event_receiver.try_recv() {
            // Our own selection comes back as an offer
            let own = state
                .clipboard_source
                .as_ref()
                .is_some_and(|(_, value)| *value == data);
            if !own {
                self.clipboard_last_value = Some(data);
            }
        }

        match self.clipboard_config {
            ClipboardConfig::Deny => {}
            ClipboardConfig::Allow => {
                if let Some(data) = self.clipboard_last_value.take() {
                    events.push(tunnel::MessageClient {
                        msg: Some(tunnel::message_client::Msg::Clipboard(
                            tunnel::EventClipboard { data },
                        )),
                    });
                }
            }
            ClipboardConfig::Trig => {
                if let (true, Some(data)) = (state.clipboard_trig, &self.clipboard_last_value) {
                    events.push(tunnel::MessageClient {
                        msg: Some(tunnel::message_client::Msg::Clipboard(
                            tunnel::EventClipboard {
                                data: data.to_owned(),
                            },
                        )),
                    });
                }
                state.clipboard_trig = false;
            }
        }

        Ok(tunnel::MessagesClient {
            msgs: events,
            fido_reports: Vec::new(),
        })
    }

    fn display_stats(&self) -> bool {
        self.state.display_stats
    }

    fn printfile(&self, file: &str) -> Result<()> {
        info!("Print file {:?}", file);
        Ok(())
    }
}

impl CompositorHandler for WaylandState {
    fn scale_factor_changed(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _surface: &wl_surface::WlSurface,
        new_factor: i32,
    ) {
        // The fractional scale, when available, is the precise one
        if self.fractional_scale.is_none() {
            self.set_scale(new_factor as f64);
        }
    }

    fn transform_changed(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _surface: &wl_surface::WlSurface,
        _new_transform: wl_output::Transform,
    ) {
    }

    fn frame(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _surface: &wl_surface::WlSurface,
        _time: u32,
    ) {
    }

    fn surface_enter(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        surface: &wl_surface::WlSurface,
        output: &WlOutput,
    ) {
        if surface == self.window.wl_surface() {
            self.current_output = Some(output.clone());
        }
    }

    fn surface_leave(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _surface: &wl_surface::WlSurface,
        _output: &WlOutput,
    ) {
    }
}

impl OutputHandler for WaylandState {
    fn output_state(&mut self) -> &mut OutputState {
        &mut self.output_state
    }

    fn new_output(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _output: WlOutput) {}

    fn update_output(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _output: WlOutput) {}

    fn output_destroyed(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _output: WlOutput) {
    }
}

impl WindowHandler for WaylandState {
    fn request_close(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _window: &Window) {
        self.closed = true;
    }

    fn configure(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _window: &Window,
        configure: WindowConfigure,
        _serial: u32,
    ) {
        if let (Some(width), Some(height)) = configure.new_size {
            let size = (width.get(), height.get());
            if size != self.logical_size {
                debug!("Configure {:?}", size);
                if self.configured {
                    self.resized = true;
                }
                self.logical_size = size;
            }
        }
        self.configured = true;
        self.need_update = true;
    }
}

impl SeatHandler for WaylandState {
    fn seat_state(&mut self) -> &mut SeatState {
        &mut self.seat_state
    }

    fn new_seat(&mut self, _conn: &Connection, qh: &QueueHandle<Self>, seat: WlSeat) {
        self.adopt_seat(qh, &seat);
    }

    fn new_capability(
        &mut self,
        _conn: &Connection,
        qh: &QueueHandle<Self>,
        seat: WlSeat,
        capability: Capability,
    ) {
        // Seats present at startup only show up here, not in new_seat
        self.adopt_seat(qh, &seat);
        if Some(&seat) != self.seat.as_ref() {
            return;
        }
        match capability {
            Capability::Keyboard if self.keyboard.is_none() => {
                self.keyboard = Some(seat.get_keyboard(qh, ()));
                if self.grab_keyboard {
                    self.set_inhibitor(qh, true);
                }
            }
            Capability::Pointer if self.pointer.is_none() => {
                match self.seat_state.get_pointer(qh, &seat) {
                    Ok(pointer) => self.pointer = Some(pointer),
                    Err(err) => warn!("Cannot get pointer: {}", err),
                }
            }
            _ => {}
        }
    }

    fn remove_capability(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _seat: WlSeat,
        capability: Capability,
    ) {
        match capability {
            Capability::Keyboard => {
                if let Some(keyboard) = self.keyboard.take() {
                    keyboard.release();
                }
            }
            Capability::Pointer => {
                if let Some(pointer) = self.pointer.take() {
                    pointer.release();
                }
            }
            _ => {}
        }
    }

    fn remove_seat(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _seat: WlSeat) {}
}

impl Dispatch<WlKeyboard, ()> for WaylandState {
    fn event(
        state: &mut Self,
        _keyboard: &WlKeyboard,
        event: wl_keyboard::Event,
        _data: &(),
        _conn: &Connection,
        qh: &QueueHandle<Self>,
    ) {
        match event {
            // Keycodes go raw to the server, which has its own keymap
            wl_keyboard::Event::Keymap { .. } => {}
            wl_keyboard::Event::Enter { serial, .. } => {
                trace!("Focus in");
                state.input_serial = serial;
                state.need_update = true;
                // If caps/num/scroll locks have changed during out of focus,
                // force keys state synchro
                state.sync_key_locks_needed = true;
            }
            wl_keyboard::Event::Leave { .. } => {
                trace!("Focus out");
                state.release_keys();
            }
            wl_keyboard::Event::Key {
                serial,
                key,
                state: key_state,
                ..
            } => {
                state.input_serial = serial;
                let keycode = key + EVDEV_TO_X11;
                let updown = matches!(key_state, WEnum::Value(wl_keyboard::KeyState::Pressed));
                trace!("Key {} {}", keycode, updown);
                if let Some(pressed) = state.keys_state.get_mut((keycode & 0xFF) as usize) {
                    *pressed = updown;
                }
                if updown {
                    state.handle_shortcuts(qh, keycode);
                }
                state.events.push(tunnel::MessageClient {
                    msg: Some(tunnel::message_client::Msg::Key(tunnel::EventKey {
                        keycode,
                        updown,
                    })),
                });
            }
            wl_keyboard::Event::Modifiers { mods_locked, .. } => {
                state.locked_modifiers = mods_locked;
            }
            _ => {}
        }
    }
}

impl PointerHandler for WaylandState {
    fn pointer_frame(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _pointer: &WlPointer,
        events: &[PointerEvent],
    ) {
        for event in events {
            if &event.surface != self.window.wl_surface() {
                continue;
            }
            match event.kind {
                PointerEventKind::Enter { serial } => {
                    self.pointer_serial = Some(serial);
                    self.update_cursor();
                }
                PointerEventKind::Leave { .. } => {
                    self.pointer_serial = None;
                }
                PointerEventKind::Motion { .. } => {
                    let (x, y) = self.to_client(event.position);
                    // If multiple mouse moves, keep only last one
                    self.last_move = Some(tunnel::MessageClient {
                        msg: Some(tunnel::message_client::Msg::Move(tunnel::EventMove {
                            x,
                            y,
                        })),
                    });
                }
                PointerEventKind::Press { button, serial, .. }
                | PointerEventKind::Release { button, serial, .. } => {
                    self.input_serial = serial;
                    let updown = matches!(event.kind, PointerEventKind::Press { .. });
                    if let Some((_, button)) = BUTTONS.iter().find(|(code, _)| *code == button) {
                        self.button_event(event.position, *button, updown);
                    }
                }
                PointerEventKind::Axis {
                    horizontal,
                    vertical,
                    ..
                } => {
                    let steps = |discrete: i32, absolute: f64, accumulator: &mut f64| {
                        if discrete != 0 {
                            *accumulator = 0.0;
                            return discrete;
                        }
                        *accumulator += absolute;
                        let steps = (*accumulator / SCROLL_STEP) as i32;
                        *accumulator -= steps as f64 * SCROLL_STEP;
                        steps
                    };
                    let mut accumulator = self.scroll_accumulator;
                    let vertical = steps(vertical.discrete, vertical.absolute, &mut accumulator.1);
                    let horizontal =
                        steps(horizontal.discrete, horizontal.absolute, &mut accumulator.0);
                    self.scroll_accumulator = accumulator;
                    self.scroll(event.position, vertical, (4, 5));
                    self.scroll(event.position, horizontal, (6, 7));
                }
            }
        }
    }
}

impl DataDeviceHandler for WaylandState {
    fn enter(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _data_device: &WlDataDevice,
        _x: f64,
        _y: f64,
        _surface: &wl_surface::WlSurface,
    ) {
    }

    fn leave(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _data_device: &WlDataDevice) {}

    fn motion(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _data_device: &WlDataDevice,
        _x: f64,
        _y: f64,
    ) {
    }

    fn selection(&mut self, conn: &Connection, _qh: &QueueHandle<Self>, _device: &WlDataDevice) {
        let Some(offer) = self
            .data_device
            .as_ref()
            .and_then(|device| device.data().selection_offer())
        else {
            return;
        };
        let mime_type = offer.with_mime_types(|mime_types| {
            TEXT_MIME_TYPES
                .iter()
                .find(|mime| mime_types.iter().any(|offered| offered == *mime))
                .map(|mime| mime.to_string())
        });
        let Some(mime_type) = mime_type else {
            return;
        };
        let mut pipe = match offer.receive(mime_type) {
            Ok(pipe) => pipe,
            Err(err) => {
                warn!("Cannot receive the clipboard: {:?}", err);
                return;
            }
        };
        if let Err(err) = conn.flush() {
            warn!("Error in Wayland flush: {:?}", err);
        }
        // The source writes until it closes the pipe: read away from the
        // event loop
        let sender = self.clipboard_sender.clone();
        thread::spawn(move || {
            let mut data = vec![];
            match pipe.read_to_end(&mut data) {
                Ok(_) => {
                    let _ = sender.send(String::from_utf8_lossy(&data).into_owned());
                }
                Err(err) => warn!("Cannot read the clipboard: {:?}", err),
            }
        });
    }

    fn drop_performed(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _data_device: &WlDataDevice,
    ) {
    }
}

impl DataOfferHandler for WaylandState {
    fn source_actions(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _offer: &mut DragOffer,
        _actions: DndAction,
    ) {
    }

    fn selected_action(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _offer: &mut DragOffer,
        _actions: DndAction,
    ) {
    }
}

impl DataSourceHandler for WaylandState {
    fn accept_mime(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _source: &WlDataSource,
        _mime: Option<String>,
    ) {
    }

    fn send_request(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        source: &WlDataSource,
        _mime: String,
        fd: WritePipe,
    ) {
        let Some((_, data)) = self
            .clipboard_source
            .as_ref()
            .filter(|(own, _)| own.inner() == source)
        else {
            return;
        };
        let data = data.clone();
        // The reader may be slow to drain the pipe: write away from the event
        // loop
        thread::spawn(move || {
            let mut file = File::from(OwnedFd::from(fd));
            if let Err(err) = file.write_all(data.as_bytes()) {
                warn!("Cannot write the clipboard: {:?}", err);
            }
        });
    }

    fn cancelled(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, source: &WlDataSource) {
        if self
            .clipboard_source
            .as_ref()
            .is_some_and(|(own, _)| own.inner() == source)
        {
            self.clipboard_source = None;
        }
    }

    fn dnd_dropped(&mut self, _conn: &Connection, _qh: &QueueHandle<Self>, _source: &WlDataSource) {
    }

    fn dnd_finished(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _source: &WlDataSource,
    ) {
    }

    fn action(
        &mut self,
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
        _source: &WlDataSource,
        _action: DndAction,
    ) {
    }
}

impl Dispatch<WpFractionalScaleV1, ()> for WaylandState {
    fn event(
        state: &mut Self,
        _proxy: &WpFractionalScaleV1,
        event: wp_fractional_scale_v1::Event,
        _data: &(),
        _conn: &Connection,
        _qh: &QueueHandle<Self>,
    ) {
        if let wp_fractional_scale_v1::Event::PreferredScale { scale } = event {
            // In 120ths
            state.set_scale(scale as f64 / 120.0);
        }
    }
}

impl ShmHandler for WaylandState {
    fn shm_state(&mut self) -> &mut Shm {
        &mut self.shm
    }
}

impl ProvidesRegistryState for WaylandState {
    fn registry(&mut self) -> &mut RegistryState {
        &mut self.registry_state
    }

    registry_handlers!(OutputState, SeatState);
}

delegate_compositor!(WaylandState);
delegate_output!(WaylandState);
delegate_shm!(WaylandState);
delegate_seat!(WaylandState);
delegate_pointer!(WaylandState);
delegate_data_device!(WaylandState);
delegate_xdg_shell!(WaylandState);
delegate_xdg_window!(WaylandState);
delegate_registry!(WaylandState);

delegate_noop!(WaylandState: WpViewporter);
delegate_noop!(WaylandState: WpViewport);
delegate_noop!(WaylandState: WpFractionalScaleManagerV1);
delegate_noop!(WaylandState: ZwpKeyboardShortcutsInhibitManagerV1);
delegate_noop!(WaylandState: ignore ZwpKeyboardShortcutsInhibitorV1);

#[cfg(test)]
mod tests {
    use super::*;

    fn pixel(canvas: &[u8], width: usize, x: usize, y: usize) -> [u8; 4] {
        let offset = (y * width + x) * 4;
        [
            canvas[offset],
            canvas[offset + 1],
            canvas[offset + 2],
            canvas[offset + 3],
        ]
    }

    #[test]
    fn mask_clears_outside_and_opens_inside() {
        let (width, height) = (8, 4);
        let mut canvas = vec![0x40; width * height * 4];
        let rects = [
            Rect {
                x: 1,
                y: 1,
                width: 3,
                height: 2,
            },
            // Overlaps the first one and runs past the right edge
            Rect {
                x: 3,
                y: 2,
                width: 10,
                height: 1,
            },
        ];
        apply_seamless_mask(&mut canvas, width, height, &rects);
        assert_eq!(pixel(&canvas, width, 0, 0), [0, 0, 0, 0]);
        assert_eq!(pixel(&canvas, width, 0, 1), [0, 0, 0, 0]);
        assert_eq!(pixel(&canvas, width, 1, 1), [0x40, 0x40, 0x40, 0xFF]);
        assert_eq!(pixel(&canvas, width, 3, 1), [0x40, 0x40, 0x40, 0xFF]);
        assert_eq!(pixel(&canvas, width, 4, 1), [0, 0, 0, 0]);
        assert_eq!(pixel(&canvas, width, 7, 2), [0x40, 0x40, 0x40, 0xFF]);
        assert_eq!(pixel(&canvas, width, 2, 3), [0, 0, 0, 0]);
    }

    #[test]
    fn areas_scale_to_the_target_size() {
        let area = Area {
            id: 1,
            size: (100, 50),
            position: (200, -10),
            mapped: true,
            is_app: true,
            name: String::new(),
        };
        let hidden = Area {
            mapped: false,
            ..area.clone()
        };
        let rects = areas_to_rects(&[(1, area), (2, hidden)], (2000, 1000), (1000, 500));
        assert_eq!(rects, vec![(100, -5, 50, 25)]);
    }
}
