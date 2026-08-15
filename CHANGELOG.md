# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
