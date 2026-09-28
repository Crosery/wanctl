# 0015 — First contact is checked with a device-shown code, not a fingerprint a human reads aloud

Date: 2026-09-28
Status: implemented on the feature branch; not released

## Problem

First contact is the one step in wanctl where the product asks a human to do
something hard, and does it at the worst possible moment.

A controller that has never dialled a device stops with `DEVICE IDENTITY
CONFIRMATION REQUIRED`, carrying the `SHA256:<43 base64 characters>` fingerprint
the device presented. The only way past it is for a human to compare that string
with the same string as shown on the device — the Android app's 连接详情 screen,
`wanctl id`, or the agent's startup banner — and then run `wanctl trust server
--target … --fingerprint …`.

Three things follow from that:

1. Forty-three base64 characters have no structure a person can chunk, and one
   wrong character is indistinguishable from an impersonation. The comparison
   decays into a glance at two screens.
2. Nothing tells the reader where the device's copy of the value lives. The
   refusal names a target and a fingerprint, not a place to look.
3. An AI-driven controller cannot do this part at all. It has no camera and no
   phone: the human has to move a 43-character string from a phone screen into a
   chat window by hand, which is where the conversation stalls and the human
   says "just connect" — the exact failure ADR 0002 named: "Whether that is a
   real defence now depends on people actually comparing them".

## Decision

Derive a **nine-digit verification code** from the certificate that dial
presented, have the device print its own derivation of the same code locally, and
let the human compare those instead — with the code checked on this side, not
merely displayed.

- The controller draws a **verification number** (six digits, fresh per dial)
  and derives `code = SHA256("wanctl/verify/v1" ‖ fingerprint ‖ number)`, first
  nine decimal digits. Both are printed beside the fingerprint, with the exact
  command that uses them.
- On the device, `wanctl verify <number>` prints the same derivation computed
  from that installation's **own certificate**, and names the number it answered.
  It is local by construction: no relay, no agent, no network, just the identity
  files — which is what makes it usable on exactly the device whose identity is
  not yet trusted. The Android app runs the same command from 连接详情 → 连接校验,
  so a phone shows the code on its own screen.
- On the controller, `wanctl trust server --target X --number N --code C`
  re-dials, derives the code from the certificate answering now, and pins only on
  a match. A mismatch is `VERIFICATION CODE MISMATCH` and pins nothing. With no
  flags on a terminal, the same check runs as one exchange: print the number, ask
  for the code the device shows, pin on a match — the code this side would accept
  is deliberately not printed there, so what is typed has to come off the device.
- `--fingerprint` keeps working, for a device whose wanctl predates `wanctl
  verify` and for anyone who would rather compare the whole string.
- The MCP tool takes `number` and `code` and treats `fingerprint` as optional, so
  a model can resolve first contact from the user's spoken answer alone. A call
  carrying neither proof is refused.

**Why the number, and not a truncated fingerprint.** Truncating the fingerprint
(or encoding it as words) is forgeable: the relay already knows the real device's
fingerprint from its own device records, so an attacker grinds a key pair whose
truncated digest matches and the human's short comparison succeeds. Binding a
number that is drawn per dial and never touches the wire makes precomputation
useless: to win, a substituted certificate must satisfy
`code(attacker_fp, N) == code(real_fp, N)` for a number that did not exist when
the certificate was chosen — a 1e-9 collision, per dial, with a visible mismatch
every other time.

**What does not change.** The pin, its `--replace`-is-a-human-decision rule, the
pairing/approval gate, the trust store, and the rule that first contact sends
nothing: no hello, no probe, nothing is sent to an endpoint this controller has
not pinned. The number reaches the device through the human; both derivations are
local; no relay, portal or resolver can forge a match.

## Rejected alternatives

- **Truncate the fingerprint** (`transport.ShortFingerprint`): grindable, and it
  would replace a real check with a decoration.
- **Send a verification hello before pinning**, so the device can answer with a
  code bound to the dial: one comparison instead of two, but it breaks the
  documented "nothing was sent" guarantee and hands any attacker an
  unauthenticated way to make a device prompt its owner.
- **Let the device's pairing approval imply the pin**: rejected by ADR 0002, and
  on a device with auto-trust on (the Android app's default for a controller the
  owner has already allowed) the approval is silent, so it authenticates nothing.
- **Read the code from the portal's device record**: the seed and the comparison
  would come from the party the pin protects against.
- **A QR code**: a terminal has no scanner, and a phone cannot scan the value it
  is being asked to compare.

## Consequences

- A device older than this change shows no code; the controller's refusal still
  carries the fingerprint command, and an operator whose device cannot answer
  keeps the old flow. `wanctl trust server --fingerprint` therefore stays
  supported, not deprecated.
- The Android app gains one screen (连接详情 → 连接校验) that runs the bundled
  binary locally. It needs no new IPC: the app already runs short commands and
  reads their stdout.
- `wanctl verify` is CLI-only and deliberately absent from the MCP surface: it is
  run *on the device*, by a human standing there.
- The code is a comparison aid, not a secret and not a proof of possession: it is
  a function of the public certificate. What it proves is that *this* controller,
  holding the certificate it was just shown, and *that* device, printing from its
  own identity, derived the same value for a number the controller drew.

## Evidence

- `internal/transport/verifycode_test.go`: the derivation is a pure function of
  (fingerprint, number), moves with both inputs, refuses anything that is not a
  fingerprint or a six-digit number, and spreads across the digit space.
- `internal/client/verification_e2e_test.go`: over a real relay and a real agent,
  first contact hands over a number and the device's code; a code that did not
  come off the device pins nothing; the device's own code pins it and the device
  is then drivable; a device reinstalled after the number was issued is refused
  as an identity change; a number carried in from an earlier refusal is checked
  against the certificate answering now.
- `verify_cli_test.go`: the same journey through the real binary in separate
  processes, including `wanctl verify` run against the agent's own config dir
  printing the code the controller derived.
- `internal/mcp/trustcode_test.go`: the HTTP refusal carries the number, the
  code, and the device-side command without naming a CLI the model cannot run;
  the handler refuses a pin that nothing was verified for.
