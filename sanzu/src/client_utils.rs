use sanzu_common::tunnel;

use anyhow::Result;
use std::{cmp::Ordering, collections::HashMap};

/// X11 keycodes used to detect the paste shortcuts (Ctrl+V, Shift+Insert)
const KEY_CTRL_L: usize = 37;
const KEY_CTRL_R: usize = 105;
const KEY_SHIFT_L: usize = 50;
const KEY_SHIFT_R: usize = 62;
const KEY_ALT_L: usize = 64;
const KEY_ALT_R: usize = 108;
const KEY_V: usize = 55;
const KEY_INSERT: usize = 118;

/// Returns true if `keycode`, pressed along with the keys of `keys_state`, is a
/// paste shortcut: Ctrl+V (Ctrl+Shift+V in terminals) or Shift+Insert
pub fn is_paste_shortcut(keys_state: &[bool], keycode: usize) -> bool {
    let pressed = |key: usize| keys_state.get(key).copied().unwrap_or(false);
    let ctrl = pressed(KEY_CTRL_L) || pressed(KEY_CTRL_R);
    let shift = pressed(KEY_SHIFT_L) || pressed(KEY_SHIFT_R);
    let alt = pressed(KEY_ALT_L) || pressed(KEY_ALT_R);
    !alt && ((ctrl && keycode == KEY_V) || (shift && !ctrl && keycode == KEY_INSERT))
}

/// Holds information on a server side window.
///
/// TODO: for now, we only support rectangle windows.
#[derive(Clone, Debug)]
pub struct Area {
    pub id: usize,
    pub size: (u16, u16),
    pub position: (i16, i16),
    pub mapped: bool,
    pub is_app: bool,
    pub name: String,
}

impl Eq for Area {}

impl Ord for Area {
    fn cmp(&self, other: &Self) -> Ordering {
        let ret = self.id.cmp(&other.id);
        if ret != Ordering::Equal {
            return ret;
        }

        let ret = self.size.cmp(&other.size);
        if ret != Ordering::Equal {
            return ret;
        }
        let ret = self.position.cmp(&other.position);
        if ret != Ordering::Equal {
            return ret;
        }
        let ret = self.mapped.cmp(&other.mapped);
        if ret != Ordering::Equal {
            return ret;
        }
        let ret = self.is_app.cmp(&other.is_app);
        if ret != Ordering::Equal {
            return ret;
        }
        self.name.cmp(&other.name)
    }
}

impl PartialEq for Area {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
            && self.position == other.position
            && self.size == other.size
            && self.mapped == other.mapped
            && self.is_app == other.is_app
            && self.name == other.name
    }
}

impl PartialOrd for Area {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        let ret = self.id.partial_cmp(&other.id);
        if ret != Some(Ordering::Equal) {
            return ret;
        }

        let ret = self.size.partial_cmp(&other.size);
        if ret != Some(Ordering::Equal) {
            return ret;
        }
        let ret = self.position.partial_cmp(&other.position);
        if ret != Some(Ordering::Equal) {
            return ret;
        }
        let ret = self.mapped.partial_cmp(&other.mapped);
        if ret != Some(Ordering::Equal) {
            return ret;
        }
        let ret = self.is_app.partial_cmp(&other.is_app);
        if ret != Some(Ordering::Equal) {
            return ret;
        }
        self.name.partial_cmp(&other.name)
    }
}

pub trait Client {
    fn size(&self) -> (u16, u16);
    /// Change the client cursor
    ///
    /// * `cursor_data` - A list of u8. A pixel is 4 u8 (rgba) group.
    /// * `hot` - The cursor center position
    ///
    /// TODO: For now, this x11 code transform the rgba into 1 bit cursor (black /
    /// white) and 1 bit (transparent / not transparent) cursor shape.
    fn set_cursor(&mut self, cursor_data: &[u8], size: (u32, u32), hot: (u16, u16)) -> Result<()>;

    /// Set the client image to `img`, with a size of `width`x`height` in 24bpp (rgb)
    /// Inform `client_info` we will need a graphic update
    fn set_img(&mut self, img: &[u8], size: (u32, u32)) -> Result<()>;
    /// Update the client graphic:
    /// - update the local window shape to match remote windows in seamless
    /// - update the x11 image if needed
    fn update(&mut self, areas: &HashMap<usize, Area>) -> Result<()>;

    /// Set the client clipboard to the desired `data`
    fn set_clipboard(&mut self, data: &str) -> Result<()>;

    /// Retrieve the client x11 events and serialize them using protobuf
    ///
    /// Every monitored client event is sent to the server, except the MouseMove
    /// event. Only the last movement is sent. As we may have a "quick" client
    /// mouse, multiple movements may be captured between two client frames. We
    /// don't want to send a list of mouse movement to the server in this case but
    /// only the last one. This may give server side quirks. The drawback is that we
    /// may have "shortcuts" in the remote mouse position (for example, if you are
    /// drawing a circle on a remote Gimp, this may give a polygon)
    fn poll_events(&mut self) -> Result<tunnel::MessagesClient>;

    fn display_stats(&self) -> bool;

    /// In clipboard trig mode, returns true (once) if the user pasted while the
    /// local clipboard has not been sent with Ctrl+Alt+Shift+C or V
    fn clipboard_warning(&mut self) -> bool;

    /// Callback to print file
    fn printfile(&self, file: &str) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys(pressed: &[usize]) -> Vec<bool> {
        let mut keys_state = vec![false; 0x100];
        for key in pressed {
            keys_state[*key] = true;
        }
        keys_state
    }

    #[test]
    fn paste_shortcuts() {
        assert!(is_paste_shortcut(&keys(&[KEY_CTRL_L]), KEY_V));
        assert!(is_paste_shortcut(&keys(&[KEY_CTRL_R, KEY_SHIFT_L]), KEY_V));
        assert!(is_paste_shortcut(&keys(&[KEY_SHIFT_R]), KEY_INSERT));
        assert!(!is_paste_shortcut(&keys(&[]), KEY_V));
        assert!(!is_paste_shortcut(&keys(&[]), KEY_INSERT));
        assert!(!is_paste_shortcut(&keys(&[KEY_CTRL_L]), KEY_INSERT));
        // Ctrl+Alt+Shift shortcuts are local to the client
        assert!(!is_paste_shortcut(
            &keys(&[KEY_CTRL_L, KEY_SHIFT_L, KEY_ALT_L]),
            KEY_V
        ));
    }
}
