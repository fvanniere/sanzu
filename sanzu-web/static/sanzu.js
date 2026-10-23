// Sanzu web client: H.264 frames decoded by WebCodecs, input as JSON
// (see sanzu-web/src/session.rs for the messages)

const FRAME = 1;
const CURSOR = 2;

// KeyboardEvent.code (the physical key) to X11 keycode (evdev code + 8): the
// remote keymap gives the key its meaning, as with the native clients
const KEYCODES = (() => {
  const evdev = {
    Escape: 1, Digit1: 2, Digit2: 3, Digit3: 4, Digit4: 5, Digit5: 6, Digit6: 7,
    Digit7: 8, Digit8: 9, Digit9: 10, Digit0: 11, Minus: 12, Equal: 13,
    Backspace: 14, Tab: 15, KeyQ: 16, KeyW: 17, KeyE: 18, KeyR: 19, KeyT: 20,
    KeyY: 21, KeyU: 22, KeyI: 23, KeyO: 24, KeyP: 25, BracketLeft: 26,
    BracketRight: 27, Enter: 28, ControlLeft: 29, KeyA: 30, KeyS: 31, KeyD: 32,
    KeyF: 33, KeyG: 34, KeyH: 35, KeyJ: 36, KeyK: 37, KeyL: 38, Semicolon: 39,
    Quote: 40, Backquote: 41, ShiftLeft: 42, Backslash: 43, KeyZ: 44, KeyX: 45,
    KeyC: 46, KeyV: 47, KeyB: 48, KeyN: 49, KeyM: 50, Comma: 51, Period: 52,
    Slash: 53, ShiftRight: 54, NumpadMultiply: 55, AltLeft: 56, Space: 57,
    CapsLock: 58, F1: 59, F2: 60, F3: 61, F4: 62, F5: 63, F6: 64, F7: 65, F8: 66,
    F9: 67, F10: 68, NumLock: 69, ScrollLock: 70, Numpad7: 71, Numpad8: 72,
    Numpad9: 73, NumpadSubtract: 74, Numpad4: 75, Numpad5: 76, Numpad6: 77,
    NumpadAdd: 78, Numpad1: 79, Numpad2: 80, Numpad3: 81, Numpad0: 82,
    NumpadDecimal: 83, IntlBackslash: 86, F11: 87, F12: 88, IntlRo: 89,
    NumpadEnter: 96, ControlRight: 97, NumpadDivide: 98, PrintScreen: 99,
    AltRight: 100, Home: 102, ArrowUp: 103, PageUp: 104, ArrowLeft: 105,
    ArrowRight: 106, End: 107, ArrowDown: 108, PageDown: 109, Insert: 110,
    Delete: 111, NumpadEqual: 117, Pause: 119, IntlYen: 124, MetaLeft: 125,
    MetaRight: 126, ContextMenu: 127,
  };
  return Object.fromEntries(Object.entries(evdev).map(([code, key]) => [code, key + 8]));
})();

// MouseEvent.button to X11 button
const BUTTONS = [1, 2, 3, 8, 9];

// Wheel pixels worth one X11 wheel click: a mouse notch in Chromium; Firefox
// counts 3 lines a notch
const WHEEL_STEP = 100;
const WHEEL_LINE = WHEEL_STEP / 3;

const canvas = document.getElementById("display");
const screen = document.getElementById("screen");
const context = canvas.getContext("2d");
const statusText = document.getElementById("status");
const overlay = document.getElementById("overlay");
const overlayMessage = document.getElementById("overlay-message");

let ws = null;
let decoder = null;
let decoderConfig = null;
let waitingKey = true;
let pressed = new Set();
let wheel = { x: 0, y: 0 };
let pendingPaste = null;

function setStatus(text) {
  statusText.textContent = text;
}

function showOverlay(message) {
  overlayMessage.textContent = message;
  overlay.hidden = false;
}

function send(event) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(event));
  }
}

// Display size in device pixels, even as the encoders want
function displaySize() {
  const ratio = window.devicePixelRatio || 1;
  return {
    w: Math.max(2, Math.round(screen.clientWidth * ratio)) & ~1,
    h: Math.max(2, Math.round(screen.clientHeight * ratio)) & ~1,
  };
}

// Split an Annex B stream into NAL units
function* nalUnits(data) {
  let start = -1;
  let i = 0;
  while (i + 2 < data.length) {
    if (data[i] === 0 && data[i + 1] === 0 && data[i + 2] === 1) {
      if (start >= 0) {
        let end = i;
        if (end > start && data[end - 1] === 0) end -= 1;
        yield data.subarray(start, end);
      }
      i += 3;
      start = i;
    } else {
      i += 1;
    }
  }
  if (start >= 0 && start < data.length) yield data.subarray(start);
}

// H.264 codec string from the SPS (profile, constraints, level), and IDR presence
function inspectH264(data) {
  let codec = null;
  let key = false;
  for (const nal of nalUnits(data)) {
    const type = nal[0] & 0x1f;
    if (type === 7 && nal.length >= 4) {
      codec = "avc1." + [nal[1], nal[2], nal[3]]
        .map((byte) => byte.toString(16).padStart(2, "0")).join("");
    } else if (type === 5) {
      key = true;
    }
  }
  return { codec, key };
}

// VP9 and AV1 headers carry no level the decoder needs: pick one from the size
function levelForSize(width, height, levels) {
  const area = width * height;
  return area <= 2228224 ? levels[0] : area <= 8912896 ? levels[1] : levels[2];
}

// VP9 codec string from the uncompressed header of a key frame (profile 1
// is 4:4:4), and key frame presence
function inspectVp9(data, width, height) {
  if (data.length < 1 || data[0] >> 6 !== 2) return { codec: null, key: false };
  const profile = ((data[0] >> 5) & 1) | (((data[0] >> 4) & 1) << 1);
  const shift = profile === 3 ? 1 : 0;
  const showExisting = (data[0] >> (3 - shift)) & 1;
  const key = !showExisting && ((data[0] >> (2 - shift)) & 1) === 0;
  if (!key) return { codec: null, key };
  const level = levelForSize(width, height, ["41", "51", "61"]);
  const depth = profile >= 2 ? "10" : "08";
  return { codec: `vp09.0${profile}.${level}.${depth}`, key };
}

class BitReader {
  constructor(bytes) {
    this.bytes = bytes;
    this.pos = 0;
  }

  read(count) {
    let value = 0;
    for (let i = 0; i < count; i++) {
      const byte = this.bytes[this.pos >> 3] ?? 0;
      value = (value << 1) | ((byte >> (7 - (this.pos & 7))) & 1);
      this.pos += 1;
    }
    return value;
  }
}

// Profile, level and tier of an AV1 sequence header; the level is only read
// when no timing info precedes it
function av1SequenceCodec(obu, width, height) {
  const bits = new BitReader(obu);
  const profile = bits.read(3);
  bits.read(1); // still_picture
  const reduced = bits.read(1);
  let level = null;
  let tier = "M";
  if (reduced) {
    level = bits.read(5);
  } else if (!bits.read(1)) {
    bits.read(1); // initial_display_delay_present_flag
    bits.read(5); // operating_points_cnt_minus_1
    bits.read(12); // operating_point_idc[0]
    level = bits.read(5);
    if (level > 7 && bits.read(1)) tier = "H";
  }
  const levelText = level === null
    ? levelForSize(width, height, ["09", "13", "17"])
    : String(level).padStart(2, "0");
  return { codec: `av01.${profile}.${levelText}${tier}.08`, reduced: reduced === 1 };
}

// Low overhead AV1 stream: codec string from the sequence header, and key
// frame presence from the frame header
let av1Reduced = false;
function inspectAv1(data, width, height) {
  let codec = null;
  let key = false;
  let pos = 0;
  while (pos < data.length) {
    const header = data[pos];
    const type = (header >> 3) & 0x0f;
    const extension = (header >> 2) & 1;
    const hasSize = (header >> 1) & 1;
    pos += 1 + extension;
    let size = data.length - pos;
    if (hasSize) {
      size = 0;
      for (let i = 0; i < 8 && pos < data.length; i++) {
        const byte = data[pos++];
        size += (byte & 0x7f) * 2 ** (7 * i);
        if (!(byte & 0x80)) break;
      }
    }
    const obu = data.subarray(pos, pos + size);
    if (type === 1) {
      const sequence = av1SequenceCodec(obu, width, height);
      codec = sequence.codec;
      av1Reduced = sequence.reduced;
    } else if ((type === 3 || type === 6) && obu.length > 0) {
      // KEY_FRAME is frame_type 0, after show_existing_frame
      key = key || av1Reduced || (obu[0] & 0xe0) === 0;
    }
    pos += size;
  }
  return { codec, key };
}

// Codec announced by the server hello: h264, vp9 or av1
let streamCodec = "h264";
function inspect(data, width, height) {
  if (streamCodec === "vp9") return inspectVp9(data, width, height);
  if (streamCodec === "av1") return inspectAv1(data, width, height);
  return inspectH264(data);
}

async function configureDecoder(codec, width, height) {
  const config = { codec, codedWidth: width, codedHeight: height, optimizeForLatency: true };
  const support = await VideoDecoder.isConfigSupported(config);
  if (!support.supported) {
    throw new Error(`This browser cannot decode ${codec}: ask for another codec or yuv420p on the server`);
  }
  if (!decoder || decoder.state === "closed") {
    decoder = new VideoDecoder({
      output: (frame) => {
        if (canvas.width !== frame.displayWidth || canvas.height !== frame.displayHeight) {
          canvas.width = frame.displayWidth;
          canvas.height = frame.displayHeight;
        }
        context.drawImage(frame, 0, 0);
        frame.close();
      },
      error: (err) => {
        console.error("Decoder error", err);
        waitingKey = true;
      },
    });
  }
  decoder.configure(config);
  decoderConfig = config;
}

let decodeQueue = Promise.resolve();
let frameIndex = 0;

function onFrame(width, height, data) {
  const { codec, key } = inspect(data, width, height);
  decodeQueue = decodeQueue.then(async () => {
    if (codec && (!decoderConfig || decoderConfig.codec !== codec
        || decoderConfig.codedWidth !== width || decoderConfig.codedHeight !== height)) {
      await configureDecoder(codec, width, height);
      waitingKey = true;
    }
    if (!decoder || decoder.state !== "configured") return;
    if (waitingKey && !key) return;
    waitingKey = false;
    decoder.decode(new EncodedVideoChunk({
      type: key ? "key" : "delta",
      timestamp: frameIndex++,
      data,
    }));
  }).catch((err) => {
    console.error(err);
    showOverlay(err.message);
  });
}

// Premultiplied BGRA from the server to a CSS cursor
function onCursor(width, height, xhot, yhot, data) {
  const image = new ImageData(width, height);
  for (let i = 0; i < width * height * 4; i += 4) {
    const alpha = data[i + 3];
    const scale = alpha ? 255 / alpha : 0;
    image.data[i] = Math.min(255, data[i + 2] * scale);
    image.data[i + 1] = Math.min(255, data[i + 1] * scale);
    image.data[i + 2] = Math.min(255, data[i] * scale);
    image.data[i + 3] = alpha;
  }
  const cursorCanvas = document.createElement("canvas");
  cursorCanvas.width = width;
  cursorCanvas.height = height;
  cursorCanvas.getContext("2d").putImageData(image, 0, 0);
  canvas.style.cursor = `url(${cursorCanvas.toDataURL()}) ${xhot} ${yhot}, default`;
}

function onBinary(buffer) {
  const view = new DataView(buffer);
  const kind = view.getUint8(0);
  const field = (index) => view.getUint32(1 + index * 4, true);
  if (kind === FRAME) {
    onFrame(field(0), field(1), new Uint8Array(buffer, 9));
  } else if (kind === CURSOR) {
    onCursor(field(0), field(1), field(2), field(3), new Uint8Array(buffer, 17));
  }
}

function onText(text) {
  const message = JSON.parse(text);
  if (message.t === "hello") {
    streamCodec = message.codec;
    setStatus(`Connected (${message.codec})`);
  } else if (message.t === "clipboard") {
    navigator.clipboard?.writeText(message.data).catch((err) => {
      console.warn("Cannot write the clipboard", err);
    });
  } else if (message.t === "error") {
    showOverlay(message.message);
  }
}

function connect() {
  overlay.hidden = true;
  setStatus("Connecting…");
  if (!("VideoDecoder" in window)) {
    showOverlay("This browser lacks WebCodecs (VideoDecoder): use a recent Chromium, Firefox or Safari");
    return;
  }
  const scheme = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${scheme}//${location.host}/ws`);
  ws.binaryType = "arraybuffer";
  ws.onopen = () => {
    send({ t: "hello", ...displaySize() });
    canvas.focus();
  };
  ws.onmessage = (event) => {
    if (typeof event.data === "string") onText(event.data);
    else onBinary(event.data);
  };
  ws.onclose = () => {
    setStatus("Disconnected");
    releaseAll();
    if (overlay.hidden) showOverlay("Session closed");
    decoderConfig = null;
    if (decoder && decoder.state !== "closed") decoder.close();
    decoder = null;
  };
}

// Canvas pixel under the mouse, the frame being letterboxed in the canvas box
function position(event) {
  const rect = canvas.getBoundingClientRect();
  const scale = Math.min(rect.width / canvas.width, rect.height / canvas.height) || 1;
  const left = (rect.width - canvas.width * scale) / 2;
  const top = (rect.height - canvas.height * scale) / 2;
  const clamp = (value, max) => Math.max(0, Math.min(max - 1, Math.round(value)));
  return {
    x: clamp((event.clientX - rect.left - left) / scale, canvas.width),
    y: clamp((event.clientY - rect.top - top) / scale, canvas.height),
  };
}

function releaseAll() {
  for (const key of pressed) send({ t: "key", k: key, d: false });
  pressed.clear();
}

function keyEvent(event, down) {
  const key = KEYCODES[event.code];
  if (key === undefined) return;
  event.preventDefault();
  if (down) pressed.add(key);
  else pressed.delete(key);
  send({ t: "key", k: key, d: down });
}

canvas.addEventListener("keydown", (event) => {
  // Ctrl+V / Shift+Insert: let the browser fire "paste" first, so that the
  // server gets the local clipboard before the keystroke
  const paste = (event.ctrlKey && event.code === "KeyV")
    || (event.shiftKey && event.code === "Insert");
  if (paste && !event.repeat) {
    pendingPaste = event;
    setTimeout(() => {
      if (pendingPaste === event) {
        pendingPaste = null;
        keyEvent(event, true);
      }
    }, 150);
    return;
  }
  keyEvent(event, true);
});
canvas.addEventListener("keyup", (event) => keyEvent(event, false));
document.addEventListener("paste", (event) => {
  const data = event.clipboardData?.getData("text");
  if (data) send({ t: "clipboard", data });
  if (pendingPaste) {
    const key = pendingPaste;
    pendingPaste = null;
    keyEvent(key, true);
  }
  event.preventDefault();
});
canvas.addEventListener("blur", releaseAll);

canvas.addEventListener("mousemove", (event) => {
  send({ t: "move", ...position(event) });
});
canvas.addEventListener("mousedown", (event) => {
  canvas.focus();
  const button = BUTTONS[event.button];
  if (button) send({ t: "button", ...position(event), b: button, d: true });
  event.preventDefault();
});
canvas.addEventListener("mouseup", (event) => {
  const button = BUTTONS[event.button];
  if (button) send({ t: "button", ...position(event), b: button, d: false });
  event.preventDefault();
});
canvas.addEventListener("contextmenu", (event) => event.preventDefault());
canvas.addEventListener("wheel", (event) => {
  event.preventDefault();
  const unit = event.deltaMode === WheelEvent.DOM_DELTA_PIXEL ? 1
    : event.deltaMode === WheelEvent.DOM_DELTA_LINE ? WHEEL_LINE : WHEEL_STEP;
  wheel.x += event.deltaX * unit;
  wheel.y += event.deltaY * unit;
  const at = position(event);
  const click = (button) => {
    send({ t: "button", ...at, b: button, d: true });
    send({ t: "button", ...at, b: button, d: false });
  };
  while (wheel.y <= -WHEEL_STEP) { click(4); wheel.y += WHEEL_STEP; }
  while (wheel.y >= WHEEL_STEP) { click(5); wheel.y -= WHEEL_STEP; }
  while (wheel.x <= -WHEEL_STEP) { click(6); wheel.x += WHEEL_STEP; }
  while (wheel.x >= WHEEL_STEP) { click(7); wheel.x -= WHEEL_STEP; }
}, { passive: false });

let resizeTimer = null;
new ResizeObserver(() => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => send({ t: "resize", ...displaySize() }), 300);
}).observe(screen);

document.getElementById("fullscreen").addEventListener("click", async () => {
  await document.documentElement.requestFullscreen();
  // Chromium: keep Alt+Tab, Escape... for the remote desktop while fullscreen
  await navigator.keyboard?.lock?.().catch(() => {});
  canvas.focus();
});
document.getElementById("reconnect").addEventListener("click", connect);

connect();
