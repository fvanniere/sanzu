# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Add debug-level FIDO traffic diagnostics with directions, CTAPHID channels,
  command and status names, payload sizes, report counts, transaction timing,
  and PIN broker state transitions. Sensitive payload contents and relying-party
  identifiers remain omitted.

### Security
- Broker and server: the TLS client identity is read from the leaf
  certificate, the only one verified by rustls, instead of the last
  certificate of the chain sent by the client. A client could append a
  self-signed certificate naming another account and log in as that account.
  Chains longer than 4 certificates are refused.
- FIDO relay: allowlist of the commands the remote session may send to the
  workstation authenticator. CTAPHID PING, MSG, INIT, WINK, CBOR and CANCEL
  pass; LOCK and the vendor commands (0x40-0x7f) get a CTAPHID error. CTAP2
  MakeCredential, GetAssertion, GetNextAssertion, GetInfo, ClientPIN and
  Selection pass; Reset, Config, CredentialManagement, BioEnrollment,
  LargeBlobs and the vendor commands are answered locally with
  `CTAP1_ERR_INVALID_COMMAND`. GetInfo no longer advertises these features.
- Server (Linux): the X server joined through `DISPLAY` must run as the uid
  of `sanzu_server` (or root), checked with `SO_PEERCRED` on the socket.
  x11rb tries the abstract socket `@/tmp/.X11-unix/X<n>` first, which any
  process of the network namespace may create: another account squatting a
  free display would otherwise receive the MIT cookie and the input events.

### Changed
- CI: each build of `main` gets its own Debian revision, `1+git<pipeline
  iid>`, and is published under the registry version
  `<version>-1+git<pipeline iid>`. Every commit of main was published as
  `<version>-1`, which the lab repository refused as a duplicate. Release tags
  keep the `-1` revision.

### Fixed
- FIDO traces: the CTAPHID command names (PING, LOCK, CANCEL, KEEPALIVE) used
  wrong codes.

## [0.2.17] - 2026-10-23

### Changed
- CI: the Debian package job runs only on runners tagged `online`, as it
  downloads Debian packages, cargo-deb and crates.

## [0.2.16] - 2026-10-23

### Added
- Server: AV1 (`libsvtav1`, `libaom-av1`, `av1_nvenc`, `av1_qsv`, `av1_amf`)
  and VP9 (`libvpx-vp9`, `vp9_qsv`) encoders. The client decodes AV1 with
  dav1d.
- sanzu-web: VP9 and AV1 decoding with WebCodecs. VP9 4:4:4 gives browsers a
  sharp image, which H.264 4:4:4 cannot.
- Low latency `libsvtav1` and `libvpx-vp9` sections in `sanzu.toml`, and
  recommended settings without GPU encoding in the README.

### Fixed
- Client: decode the frame as soon as the FFmpeg parser returns it. The AV1
  and VP9 parsers return it on the call that consumes the input, and the next
  call, with no input left, dropped it.

## [0.2.15] - 2026-10-23

### Added
- Client, clipboard `trig` mode: pasting (Ctrl+V, Ctrl+Shift+V, Shift+Insert)
  while the local clipboard has not been sent displays a flash message, in
  French, at the top of the session for 3 seconds (X11, Wayland and Windows
  clients).
- Client, clipboard `trig` mode: Ctrl+Alt+Shift+V sends the local clipboard,
  like Ctrl+Alt+Shift+C.

### Changed
- The client OSD (stats, flash messages) uses the ISO 8859-1 font, to display
  accented characters.

## [0.2.14] - 2026-10-22

### Added
- `sanzu-web` Debian package: binary, `sanzu-web.service` unit installed
  disabled, and examples under `/usr/share/doc/sanzu-web/examples`. The CI
  builds and publishes it with the three other packages.

## [0.2.13] - 2026-10-22

### Added
- `sanzu-web` (demo): the sanzu client in a browser, in the manner of
  Guacamole. The gateway logs users in with PAM (login / password) or OpenID
  Connect (authorization code with PKCE), starts their server through the
  `sanzu_broker` `on_connect` callback and relays the session over a
  WebSocket; the browser decodes the H.264 frames with WebCodecs. Keyboard,
  mouse, wheel, cursor, resize and clipboard are supported; not seamless
  mode, FIDO, Kerberos nor sound. The server for browsers needs
  `pixel_format = "yuv420p"`. Not packaged yet.

## [0.2.12] - 2026-10-22

### Added
- Native Wayland client (prototype), seamless mode included: one fullscreen
  surface, transparent and click-through outside the remote windows.
  `wp_viewporter` scales the frame, so `--zoom` and fractional output scales
  cost no CPU. Keyboard, mouse, wheel, ARGB cursor and clipboard follow the
  X11 client; `--monitor`, Ctrl+Alt+Shift+N and `--grab-keyboard` work on
  Wayland outputs.
- `--backend auto|wayland|x11` (Linux): `auto` uses Wayland when
  `WAYLAND_DISPLAY` is set and falls back to X11; `x11` runs through XWayland
  in a Wayland session. No new runtime library: the Wayland protocol is
  implemented in Rust.

### Known limitations
- Wayland client: no primary selection, no Scroll Lock synchronisation, cursor
  not scaled to the output; keyboard and mouse still to be validated on Plasma.

## [0.2.11] - 2026-10-22

### Added
- X11 client: `--monitor <index|output>` opens the client on one monitor,
  named by its `xrandr --listmonitors` index or its output name (RandR 1.5).
- X11 client: Ctrl+Alt+Shift+N moves the client to the next monitor, also
  in fullscreen, which KWin otherwise refuses to move; in seamless mode the
  window had to leave fullscreen and be moved from the window menu.
- X11 client: set `WM_CLASS` (`sanzu_client`/`Sanzu`) and `_NET_WM_NAME`, so
  window manager rules can match the client whatever its title.

## [0.2.10] - 2026-10-11

### Security
- Remove `--fido-passthrough`. It forwarded the authenticator untouched and
  let the remote session prompt for the PIN, the very exposure the local PIN
  broker exists to prevent; no released build may offer it.
- Keep the PIN out of freed memory: the pinentry output, which carries it, is
  now wiped on drop and read into a buffer that is never reallocated, and the
  decoded PIN is moved, not copied, into its wiped string.
- Log CTAP payload sizes only. Trace level used to dump them in hexadecimal,
  with the relying party, the user name and display name of new credentials
  and credential identifiers; the relying party is also gone from the debug
  log of a token request.

### Fixed
- Name the ClientPIN subcommands as CTAP 2.1 does: 0x06 is
  `getPinUvAuthTokenUsingUvWithPermissions` and 0x09
  `getPinUvAuthTokenUsingPinWithPermissions`; the code had them swapped. Both
  reach the same local prompt, so behaviour is unchanged; names and logs were
  wrong. A test now checks the specification values written as literals.

## [0.2.9] - 2026-10-11

### Fixed
- Accept certificate chains whose CA carries name constraints. The 0.2.8
  packages embedded rustls 0.21.0 and rustls-webpki 0.100.1, which reject such
  chains with a bare `UnknownIssuer`, so the client could not connect to a
  broker certified by a name constrained CA. rustls 0.21.12, already in the
  lock file since the RUSTSEC-2024-0336 update, verifies with rustls-webpki
  0.101; this release ships it, with a regression test on a real chain.

### Changed
- Update webpki-roots to 0.25, which no longer pulls rustls-webpki 0.100: a
  single webpki version is left in the dependency graph. Drop the unused
  webpki-roots dependency of the `sanzu` crate.

### Known issues
- rustls-webpki, in every version, rejects a client certificate carrying an
  rfc822Name (email) subject alternative name when the issuing CA constrains
  that name type: it does not implement rfc822Name constraints. The broker
  then refuses the client with `NameConstraintViolation`. The CA must not
  constrain rfc822Name, or the client identity must use another name type.

## [0.2.8] - 2026-08-16

### Fixed
- Relay `getPINRetries` to the authenticator instead of rejecting it. The
  counter is read-only and discloses nothing about the PIN, and platforms read
  it before offering to verify; refusing it makes the forwarded authenticator
  look broken and the operation is abandoned.
- Answer the ClientPIN subcommands the advertised built-in verification method
  implies: `getPinUvAuthTokenUsingUvWithPermissions` for the token and
  `getUVRetries` for the counter. Both were rejected as invalid subcommands.
  Firefox takes the `clientPin` path instead, so it never hit this one.

### Known issues
- Logging into a Pocket ID instance from the remote Firefox still fails. See
  the commit message of this release for the full investigation.

## [0.2.7] - 2026-08-15

### Fixed
- Advertise `FIDO_2_1` together with the local broker's CTAP 2.1
  `pinUvAuthToken` capability so Firefox accepts the proxied authenticator.

## [0.2.6] - 2026-08-15

### Added
- Add metadata-only diagnostic logs for forwarded FIDO PIN/UV operations. The
  logs never include PINs, tokens, keys, relying-party identifiers, or CBOR
  payloads.

## [0.2.5] - 2026-08-15

### Added
- Prompt for a forwarded authenticator PIN locally on the Sanzu client through
  pinentry instead of displaying the prompt in the remote Firefox session.

### Security
- Keep the PIN and the authenticator's real `pinUvAuthToken` on the client.
- Give remote Firefox a short-lived, RP- and permission-scoped proxy token, and
  translate only verified make-credential/get-assertion proofs on the client.
- Reject unsupported remote ClientPIN operations instead of forwarding them to
  the physical authenticator.

## [0.2.4] - 2026-08-15

### Fixed
- Keep the client video session alive when a forwarded FIDO authenticator is
  unplugged, then retry it every second and resume forwarding when the same
  device is reconnected.
- Drop remote FIDO reports safely while the local authenticator is absent.

## [0.2.3] - 2026-08-15

### Added
- Add `--fido-virtual-id` on the server so multi-user deployments can assign
  each forwarded `hidraw` device to its owning session through udev.

### Security
- Validate virtual FIDO identifiers and expose them through distinct sysfs
  `phys` paths, preventing shared udev permissions between remote users.

## [0.2.2] - 2026-08-15

### Added
- Select the forwarded FIDO authenticator by HID path, case-insensitive
  manufacturer/product/serial text, or hexadecimal `VID:PID`.
- Reject ambiguous explicit FIDO selectors and list matching candidates.

## [0.2.1] - 2026-08-15

### Added
- Opt-in FIDO/CTAP HID forwarding from a Linux or Windows client to a Linux
  server, allowing remote Firefox passkey operations without USB passthrough.
- Automatic FIDO authenticator discovery and explicit selection with
  `--fido-device`.

### Security
- FIDO forwarding must be enabled explicitly with `--fido` on both endpoints.
- The client opens only the FIDO HID interface and never detaches or claims the
  complete USB device, preserving local Firefox and CCID-based GPG/PIV use.

## [0.2.0] - 2026-08-15

### Added
- Client-side zoom to encode a smaller adaptive remote desktop and upscale it locally.
- GitLab CI/CD packaging for Debian 13 (Trixie), with tagged and `main` builds published to the generic package registry.

### Changed
- Update FFmpeg bindings to 7.1 for Debian Trixie compatibility.

## [0.1.4] - 2023-05-31

### Changed
- extern-img-source short version is '-k' for all binaries
- remove duplicate '-c' option for client/proxy/server
- rename '--config_path' to '--args-config' for arguments config file
### Fixed
- Remove default listen port for sanzu_proxy (resulting in vsock err)
### Removed
- '-i' short version for "--export-video-pci" for sanzu_server

## [0.1.3] - 2023-05-16

### Changed
- loop argument renamed to keep-listen
- clipboard_config argument renamed to clipboard
- printdir argument renamed to allow-print
- import_video_shm argument renamed to extern_img_source
- shm_is_xwd argument renamed to source_is_xwd
- update to ffmpeg 6.0

### Added
- Arguments can be taken from file (--config-path) or environment variables
- Add --proto to the command line
- Add --version to the command line
- Add --title to customize client window name
- Support 32 bit rgba cursors for x11 sanzu client

### Fixed
- Multiple x11 misuse
- Dependencies listings for alpine/CentOS

## [0.1.2] - 2023-03-02

### Added/Changed

- CI: Generating binary release for alma8/alma9/alpine/debian bullseye/windows

### Fixed

- Fix windows sanzu client bad error code handling
- Fix windows memory leak
