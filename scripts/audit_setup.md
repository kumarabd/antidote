# macOS Audit Setup for Antidote Phase 4

## Overview

Phase 4 uses macOS OpenBSM audit logs to provide process-level telemetry without kernel extensions. This requires root privileges or audit access.

## Prerequisites

- macOS (audit subsystem is macOS-specific)
- Root access (for reading `/dev/auditpipe`)
- `praudit` command available (usually in `/usr/sbin/praudit`)

## Setup Steps

### 1. Check if audit is enabled

```bash
# Check audit status
sudo audit -s

# Check if praudit is available
which praudit
```

### 2. Enable audit (if needed)

Audit is usually enabled by default on macOS, but you may need to configure it:

```bash
# View current audit configuration
sudo audit -s

# Enable audit (if not already enabled)
sudo audit -e
```

### 3. Configure audit to log relevant events

The audit collector needs:
- Process execution events (execve)
- File open events
- Network connect events

These are typically enabled by default, but you can verify:

```bash
# List current audit classes
sudo audit -l
```

### 4. Run Antidote with audit support

**WARNING**: Running with root privileges has security implications. Only do this in development or with proper security measures.

```bash
# Run daemon with sudo (for audit pipe access)
sudo cargo run -p antidote-daemon

# Or build first, then run
cargo build -p antidote-daemon
sudo ./target/debug/antidote-daemon
```

### 5. Verify audit collector is active

```bash
# Check capabilities endpoint
curl http://localhost:17845/capabilities

# Should show:
# {
#   "audit_collector_active": true,
#   "proxy_active": true,
#   "fs_watcher_active": true,
#   "telemetry_confidence": "HIGH"
# }
```

## Security Considerations

1. **Root Access**: The daemon needs root to read `/dev/auditpipe`. Consider:
   - Running in a sandboxed environment
   - Using audit access groups instead of full root
   - Running only in development

2. **Audit Log Volume**: Audit logs can be high-volume. The collector includes filtering to reduce noise.

3. **Privacy**: Audit logs contain sensitive information. All data stays local, but be aware of what's being logged.

## Troubleshooting

### Audit collector not starting

- Check if `praudit` exists: `which praudit`
- Check permissions: `ls -l /dev/auditpipe`
- Check audit status: `sudo audit -s`

### No events appearing

- Verify watched processes are running
- Check if watched roots are configured
- Review daemon logs for errors

### High CPU usage

- Audit logs can be high-volume
- Consider adjusting filtering in the collector
- Check if too many processes are being watched

## Disabling Audit Mode

If you don't want to use audit telemetry:

1. Don't run with sudo
2. The daemon will fall back to Phase 3 collectors (FS watcher + proxy)
3. Telemetry confidence will be MED or LOW

## Alternative: Non-root Development

For development without root:

1. Run without sudo
2. Use Phase 3 collectors (FS watcher + proxy)
3. Telemetry confidence will be MED
4. File read events won't be available, but other telemetry works
