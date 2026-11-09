# ibuki integration contract

This directory is the source of truth for ibuki's official `devices` plugin Bridge commands. It describes commands; it is not an ibuki sandbox plugin and must not contain code that starts a process or reads credentials.

## Security boundary

- `status` and `peers` are read-only and may be shown through `ibuki bridge devices` when the dedicated wanctl profile is already configured.
- `start` and `login` are `humanOnly`. They require the person to act in the pet card; CLI/MCP must be rejected by ibuki's normal human-only gate.
- Enrollment is never automatic: `wanctl login` needs a one-time code from the portal. After a profile already has a token, an installed ibuki may run the equivalent of `wanctl start` asynchronously to keep the local agent online. It must never overwrite the token or open a browser.
- The ibuki adapter must use an absolute binary and dedicated config directory, pin `WANCTL_CONFIG_DIR` and `WANCTL_RELAY`, remove inherited token/portal overrides, use argv (never a shell string), bound output and enforce a timeout.

The JSON manifest is intentionally small and versioned. Add a command here before exposing it in ibuki; keep the Rust plugin's compiled manifest and tests in lockstep.
