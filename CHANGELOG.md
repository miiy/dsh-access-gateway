# Changelog

Versions follow [SemVer](https://semver.org/).

## 0.1.0

### Added
- Password-gated access entry: one TCP listener on a configured local address that answers a password form and then forwards to the loopback Web GUI. The settings section is called **Access**, since it serves VPN and every-interface addresses too.
- Per-connection gate: the first request head decides between the form, a rejection, and a byte pipe, so HTTP keep-alive and WebSocket upgrades pass through untouched.
- Launch-token handover: a passed login redirects to `/?token=…` with the token read from the Connection service on every redirect.
- Credential store: a configured password is checked against a hash derived in memory and only its scrypt hash is kept in `~/.dsh/dsh-access-gateway/secret.json` (0600); with no password the entry admits every request, and the Host warns once at start.
- "Require a password" in the Settings section: turned off, saving drops the stored hash and the login page disappears; turned on, a new password has to be typed.
- Login page styled with the Web GUI theme's own tokens: wordmark, one field, one button, light and dark schemes, and copy chosen from `Accept-Language`.
- Settings section in the Web GUI, built from the same primitives the built-in sections use: live listener state, address, port, session lifetime and write-only password in one form with a single Save button. A save reopens the listener on the spot, so no Host restart is needed.
- The detected interface addresses are offered as buttons under the address field, next to an automatic choice.
- Plugin listing assets: `icon.svg` named in `package.json`, a screenshot referenced from both READMEs, and `screenshots.json` for the market.
- Localized market metadata: `locale/en.json` and `locale/zh.json` carry the listing title and description for the plugin market.
- Settings route `/dsh-access-gateway/rpc`, fenced by the same admission `/api` uses, over one JSON envelope per endpoint (`get`, `save`); a save carries the optional new password with the settings.
- Settings store `~/.dsh/dsh-access-gateway/settings.json` (0600) holding the runtime values, which win over the Plugin defaults.
- `0.0.0.0` binds every interface, and each interface address is registered for the Host/Origin fence; the settings page lists every entry URL it answers on.
- The listen address registers itself in the Host/Origin fence's accepted-authority list for as long as the listener runs, so no `--trusted-host` launch flag is needed; the entry follows an address change and is removed when the plugin stops or reports the flag when no list is available.

### Changed
- A new password or session lifetime reaches the next request on its own; only a new address or port reopens the listener, so changing either one no longer drops open WebSocket connections.
- The save answer carries the listener's real state: a port that is already taken comes back as `running: false` with the reason, instead of a running entry that never came up.

### Fixed
- The credential store is written only when it lacks its key or salt; loading a profile no longer rewrites `secret.json`.
- The settings route resolves its answer before writing, so a failed save cannot leave a partial response behind.
