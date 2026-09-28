# Device identity

Every upgraded agent generates a random UUID v4 on first start and stores it in
`<WANCTL_CONFIG_DIR>/device_id` (the usual wanctl config directory when the
variable is unset). `wanctl id` prints this ID, the certificate fingerprint, and
the effective config directory. Concurrent starts publish the same ID; an invalid
existing file is an error rather than an invitation to silently reset identity.

The three concepts are independent:

- `device_id` identifies an installation. Relay routes, sharing grants, notification
  settings, audit associations, and controller pins use `namespace/device_id`.
- `--name` sets a display name (the local host name on macOS, the product model
  on Android, the hostname elsewhere).
  Portal aliases are display labels too. Both may repeat and change without
  replacing the installation.
- The certificate fingerprint authenticates the endpoint. Keeping the device ID
  while replacing the certificate still requires explicit identity confirmation.

Use `wanctl peers` to find IDs and labels, and `--target <ID>` or
`--target <namespace>/<ID>` to select an installation. A unique name or alias is
also accepted. Ambiguous names fail instead of selecting a device by registration
order. PostgreSQL-backed resolution includes offline devices in this check.
The portal uses full IDs for actions and shows a short ID beside duplicate labels.

## First contact

A controller that has never dialled an installation stops with `DEVICE IDENTITY
CONFIRMATION REQUIRED`, and nothing is sent to it until a human has confirmed
which installation answered. Two values are offered for that confirmation:

- the certificate fingerprint, `SHA256:<base64>` — precise, and forty-three
  characters compared between a phone screen and a terminal;
- a **verification number** (six digits, drawn fresh for this dial) and the
  **verification code** derived from it and the certificate the dial presented.
  `wanctl verify <number>` run on the device prints the same derivation computed
  from that installation's own certificate, locally — no relay, no agent, no
  network — and the Android app runs the same command from 连接详情 → 连接校验.
  The controller accepts a code only if it reproduces it from the certificate
  answering at that moment, so a code that did not come off that device pins
  nothing, and a device that changed in between fails as a mismatch.

The controller then records the result in its own `known_servers.json`:

```sh
wanctl trust server --target ns/device --number 482913 --code 771204638   # checked
wanctl trust server --target ns/device --fingerprint SHA256:...           # compared by eye
```

The number is drawn per dial and reaches the device through the human, never over
the relay, which is what lets nine digits carry the weight of the fingerprint
they replace: a substituted certificate would have to collide with the real
device's code for a number that did not exist when that certificate was chosen.
The fingerprint comparison remains supported for a device whose wanctl predates
`wanctl verify`.

## Upgrade

Upgrade the relay and portal together, then agents and controllers. Migration 007
renames the database routing column to `device_id`, adds mutable `display_name`
and migration metadata, and removes the alias uniqueness index. This is a schema
change: do not run old relay binaries against the migrated database. Back up the
database before deploying; rolling back requires restoring the corresponding
schema/data snapshot as well as the old binaries.

Legacy agents can keep their old routing key until upgraded. When a new agent
first reports its UUID, a legacy row in the same namespace is promoted if its
certificate fingerprint matches, whatever its old name was. Promotion preserves
the database row, alias, sharing grants, notification settings/health, and audit
associations in one transaction. The old name is kept as `legacy_name`; the
display name becomes the label the agent reports, as it does on any later rename.
A same-name device with a different fingerprint creates a separate record and
inherits none of those associations - the name is a label and cannot move an
installation's identity. The old name cannot be re-registered by an outdated
agent once promoted.

New controllers resolve targets before checking trust. A promoted row exposes its
previous target so an existing pin can be copied to the UUID target. The copied
value is always the controller's stored fingerprint, never the relay's offered
value. Existing UUID pins are never overwritten. Old controllers can still target
UUIDs, but need an explicit initial pin because they do not migrate name-based pins.

Renaming a device across its first upgrade is safe: promotion follows the
certificate, not the name. Until v0.7.1 the match also required the old name, so
a host whose name drifted on its own registered as a new device and left the old
row offline - macOS is the usual case, where `os.Hostname()` reads `localhost` or
`bogon` depending on the network. On macOS the agent now labels itself with
`scutil --get LocalHostName`, which does not drift. Repairing a database that
already split one installation in two is a manual step: delete the orphaned new
row and let the agent re-register, or re-point its associations.
A legacy record already overwritten by the old same-name collision cannot recover
the overwritten device's identity automatically.

## Protocol compatibility

Agents send `device=<UUID>`, `device_id=<UUID>`, and `name=<display name>` on both
WebSocket registration and HTTP polling. Subsequent session, notification,
pairing, and deregistration requests use the UUID. `inst` remains an ephemeral
process instance marker, not the persistent identity.

For compatibility with existing consumers, `/peers` still returns canonical
routes in `devices`, and labels in `aliases`. Device-list JSON retains `name` as a
legacy alias for the canonical route and adds explicit `device_id`,
`display_name`, and `legacy_name` fields. Consumers must not use display labels as
map keys. Legacy records have no UUID `device_id` field until upgraded.

`GET /resolve?target=...` returns the authorized canonical `target` and, after a
legacy promotion, `legacy_target`. The same owner/ACL checks used for dialing
apply. An old relay returning 404 uses the older peers-based resolution path;
other failures do not fall back to guessing a target.

## Resetting and cloning

Keeping the config directory keeps the installation ID across upgrades and
renames. Deleting the directory creates a new installation. A full VM/config
clone also copies its device ID and certificate: before starting wanctl in an
independent clone, remove its copied `device_id`, `cert.pem`, and `key.pem`, then
re-enroll it as a new installation. The original device must retain its files.
This ID is not a MAC address, hardware serial number, or proof of ownership.

## Verification

`go test ./...` covers concurrent ID creation, same-name agents across both
transports, rename/restart continuity, and certificate mismatch rejection.

To run the real PostgreSQL migration, sharing, and pin-migration checks against a
disposable PostgreSQL server:

```sh
WANCTL_TEST_POSTGRES='postgres://postgres@127.0.0.1:5432/postgres?sslmode=disable' \
  go test ./internal/relay -run TestDeviceIDPostgres -v
```

The integration test creates and removes its own schema. It requires permission
to create schemas, and does not modify existing schemas.

### Android application sandbox

Android denies hard-link creation in an ordinary app's private data directory.
Since v0.6.1, Android serializes first-time ID publishers with `device_id.lock`
and atomically renames the synced temporary file after checking for an existing
ID. The lock file is retained; kernel locks are released on process exit. Other
platforms retain hard-link publication. Existing IDs are never replaced.

For a packaged-binary regression check, start a disposable relay with
`WANCTL_TOKENS=sandbox-token:sandbox go run . relay --addr 127.0.0.1:18740`, then
run `scripts/android-id-smoke.sh /path/to/emulator-ABI.apk` with a booted emulator,
Android SDK/JDK and the usual `~/.android/debug.keystore`. The probe is a normal,
non-debuggable APK: it checks `untrusted_app` context, 16 concurrent ID processes,
persistence, and agent registration. Running the binary as `adb shell` is not
an equivalent permission test.
