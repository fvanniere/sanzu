[![Build & test](https://github.com/cea-sec/sanzu/actions/workflows/test.yml/badge.svg)](https://github.com/cea-sec/sanzu/actions/workflows/test.yml)

# Sanzu

Sanzu is a graphical remote desktop solution. It is composed of:

- a server running on Unix or Windows which can stream a X11 or a Windows GUI environment (for now the Unix version is more advanced)
- a client running on Unix or Windows which can read this stream and interact with the GUI environment

It uses modern video codecs like h264/h265 to offer a good image quality and limit its bandwidth consumption. Video compression is done through FFmpeg which allows the use of graphic cards or full featured CPU to achieve fast video compression at low latency. It also allows the use of yuv420 or yuv44 for better graphical details.


This repository contains:
- sanzu: client / server code
- sanzu-broker: a broker for sanzu
- sanzu-common: common code
- demo: demo code to quickly build and run sanzu
- build: docker scripts to build sanzu packages for several distributions

Here is the README which explains how to run the client/server manually: [Sanzu Readme](sanzu/README.md)

Here are some examples: In this case, the remote sanzu server runs under a linux system. Example configuration:
- compression: h264_qsv (intel)
- ffmpeg target bandwidth: 2000000 bits/s
- format: nv12 (yuv420)
- preset: veryfast

Screenshots are in PNG to show original compression details.

## Recommended settings without GPU encoding

When no hardware encoder is available, `libx264` on a modern multi-core CPU can still reach low latency. In the server configuration (`sanzu.toml`):

```toml
[ffmpeg.libx264]
pixel_format = "yuv420p"
preset = "superfast"
tune = "zerolatency"
x264-params = "intra-refresh=1:keyint=80:scenecut=0"
```

- `preset = "superfast"` (or `ultrafast` on slower CPUs): the `fast` preset is too slow for interactive use; these presets use a cheap motion search and a single reference frame.
- `tune = "zerolatency"`: no B-frames, no lookahead, and each frame is split in slices encoded in parallel by several threads (`sliced-threads`).
- `pixel_format = "yuv420p"`: `yuv444p` encodes twice as much chroma data; use it if colored text looks blurry, with a higher bitrate (3 to 4 Mbit/s). Browsers (sanzu-web) only decode H.264 in 4:2:0.
- `intra-refresh=1`: replaces periodic keyframes by a moving column of intra blocks, which avoids bitrate and latency spikes. `keyint` is then the number of frames needed to refresh the whole image (here 2 seconds at `max_fps = 40`).

The server logs `grab`, `encode` and `send` times for each frame: check them to see where time is spent before tuning further.

### AV1 and VP9

The server also accepts `libsvtav1` (AV1) and `libvpx-vp9` (VP9) as encoder; the client decodes them with dav1d and FFmpeg's VP9 decoder, and sanzu-web with the browser's WebCodecs.

```toml
[ffmpeg.libsvtav1]
pixel_format = "yuv420p"
preset = "8"
svtav1-params = "pred-struct=1:rc=2:scm=1"

[ffmpeg.libvpx-vp9]
pixel_format = "yuv444p"
deadline = "realtime"
cpu-used = "8"
lag-in-frames = "0"
row-mt = "1"
tune-content = "screen"
```

- AV1: `pred-struct=1` (low delay) and `rc=2` (constant bitrate) are needed for interactive use; `scm=1` enables the screen content tools (palette, intra block copy), which keep text sharp at low bitrate but only work up to preset 8. SVT-AV1 encodes 4:2:0 only.
- VP9: `yuv444p` (profile 1) keeps colored text sharp, and browsers decode it, unlike H.264 4:4:4: it is the codec to choose for a sharp image in sanzu-web.
- CPU cost, measured on an Apple M3 for a 1080p frame: about 5 ms for VP9 4:4:4, 12 ms (8 cores) to 19 ms (4 cores) for SVT-AV1 preset 8. Raise the SVT-AV1 preset (10 or more, without screen content tools) if the CPU cannot keep up.

Sanzu client running in seamless mode under windows (both windows are from the remote server)
![Alt text](misc/screenshot/sanzu_windows.png?raw=true "Sanzu client running in seamless mode under windows")

Sanzu client running in seamless mode under linux (both windows are from the remote server)
![Alt text](misc/screenshot/sanzu_linux.png?raw=true "Sanzu client running in seamless mode under linux")
