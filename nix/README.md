# Nix Configuration for Auth Service

This directory contains Nix modules and configurations for the Auth service. The setup allows for building and installing the Auth service using Nix, with proper systemd integration and configuration management.

## Files

- `auth-module.nix`: Defines the Nix module for the Auth service configuration
- `steps-module.nix`: Defines the Nix module for service startup steps and commands

## Building and Installation

### Prerequisites

- Nix package manager installed
- System with systemd (for service management)

### Installation

1. Install the package:
```bash
nix profile install .
```

2. Activate the service:
```bash
sudo auth-activate
```

### Available Commands

After installation, the following commands are available:

- `gotrue`: The auth service binary
- `gotrue-manage`: Manage the service (start/stop/restart/status)
- `auth-activate`: Run the activation script again

## Configuration

The service configuration is managed through environment variables, which are set in the Nix configuration. The main configuration file is generated at `/etc/auth.d/20_generated.env` during activation.

### Service Structure

- Binary: `/opt/gotrue/gotrue`
- Config directory: `/etc/auth.d`
- Systemd service: `gotrue.service`
- Metrics port: 9122 (automatically configured in UFW if available)

## Development

### Updating the Service

1. Modify the relevant Nix files:
   - `flake.nix` for package definition and build process
   - `auth-module.nix` for service configuration
   - `steps-module.nix` for startup steps

2. Rebuild and reinstall:
```bash
nix profile install .
sudo auth-activate
```

### Testing Changes

1. Build the package:
```bash
nix build .
```

2. The result will be in `./result/` with the following structure:
   - `bin/`: Contains the binary and management scripts
   - `share/gotrue/`: Contains the systemd service file
   - `etc/`: Contains the environment configuration

## System Requirements

- Linux system with systemd
- UFW (optional, for metrics port configuration)
- Proper permissions for the `gotrue` user (created by system image)

## Troubleshooting

1. If the service fails to start:
   - Check logs: `journalctl -u gotrue.service`
   - Verify permissions: `ls -l /opt/gotrue /etc/auth.d`
   - Check config: `cat /etc/auth.d/20_generated.env`

2. If commands are not found:
   - Verify installation: `nix profile list`
   - Check symlinks: `ls -l /usr/local/bin/gotrue*`

## Notes

- The activation script assumes the `gotrue` user exists (created by system image)
- The service runs as the `gotrue` user
- Configuration is managed through environment variables
- The service is automatically started and enabled on activation 