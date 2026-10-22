# sanzu-web

The sanzu client in a browser, in the manner of Apache Guacamole: a gateway
logs the user in, starts their sanzu server like `sanzu_broker`, and relays
the session over a WebSocket. Nothing to install on the client side.

```
browser ── HTTPS / WebSocket ──> sanzu-web ── unix socket ──> sanzu_server
 WebCodecs (H.264)               PAM / OIDC                   (started by
 keyboard, mouse, clipboard      sanzu protocol client         on_connect)
```

The gateway plays the sanzu client, as guacd does for Guacamole: the browser
gets the H.264 frames untouched and decodes them with WebCodecs (in hardware
when it can), and sends its input as small JSON messages. The messages are
described at the top of `src/session.rs`.

This is a demo. Not in the browser: seamless mode, FIDO forwarding, Kerberos,
sound and file printing.

## Authentication

- **Login / password**, checked by a PAM service (`[pam]`).
- **OpenID Connect** (`[oidc]`): authorization code flow with PKCE, state
  bound to the browser by a cookie, nonce checked. The gateway is a
  confidential client and takes the ID token straight from the token endpoint
  over TLS; as OpenID Connect Core 3.1.3.7 allows, it checks the issuer,
  audience, expiry and nonce claims but not the token signature. The user name
  comes from `username_claim` (`preferred_username` by default) and is passed
  to the session command as is: the provider decides which local account a
  user gets.

Both can be enabled together. A login is a random 256 bit token in an
`HttpOnly`, `SameSite=Lax` cookie. The login form and the WebSocket must come
from `public_origin`.

## Configuration

See `sanzu_web.toml`. `[cmd_callback.on_connect]` is the `sanzu_broker`
callback, with the same tokens (`%USERNAME%`, `%CLIENT_ADDR%`,
`%UNIX_SOCK_PATH%`): it starts a sanzu server for the user that connects back
to the unix socket, then returns:

```
sanzu_server --config server.toml --unixsock --connect-unixsock --address %UNIX_SOCK_PATH%
```

Browsers do not decode H.264 4:4:4, the default of `sanzu.toml`: the server
started for the browser needs `pixel_format = "yuv420p"` (see
`demo/server.toml`).

## Package

`cargo deb -p sanzu-web` builds the `sanzu-web` Debian package: the binary,
the `sanzu-web.service` unit, installed disabled, and the examples under
`/usr/share/doc/sanzu-web/examples`. Write `/etc/sanzu/sanzu_web.toml`, then
`systemctl enable --now sanzu-web`. The unit runs the gateway as root, like
`sanzu_broker`: PAM reads `/etc/shadow` and the session callback expects a
root owned socket in `/tmp`.

## Deployment

The gateway speaks plain HTTP. Put it behind an HTTPS reverse proxy that
forwards WebSockets, keep `listen` on 127.0.0.1 and `secure_cookie = true`.
For example with nginx:

```
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_read_timeout 1d;
}
```

PAM needs the gateway to run with enough rights for the chosen service
(`pam_unix` reads `/etc/shadow`).

## Demo

`demo/session.sh` is a throwaway `on_connect` callback: an Xvfb desktop with
an xterm, served by `sanzu_server`. It runs everything as the gateway's user,
whoever logged in: use it for a test only; a real callback starts the session
as the user (`systemd-run --uid`, `sudo`...).

```
SANZU_BIN=target/release SANZU_WEB_SERVER_CONFIG=sanzu-web/demo/server.toml \
  target/release/sanzu-web --config my_sanzu_web.toml
```

with `command_bin` pointing to `demo/session.sh`, then open
`http://localhost:8080`.

## In the browser

- Works in recent Chromium, Firefox and Safari (WebCodecs).
- The keyboard sends physical keys; the remote keymap gives their meaning.
- **Fullscreen** also locks the keyboard in Chromium, so that Alt+Tab or
  Escape reach the remote desktop.
- Clipboard: Ctrl+V in the session first sends the local clipboard to the
  server; a remote copy goes to the local clipboard.
