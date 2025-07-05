# bpftoy

A real-time eBPF-based credential monitoring tool for Linux security research. Tracks credential changes (UID/GID modifications) by hooking into the kernel's `commit_creds` function, providing visibility into privilege escalation attempts and suspicious credential operations.

## Features

- **Real-time monitoring**: Captures credential changes as they happen in the kernel
- **Intelligent filtering**: Reduces noise by filtering out routine system operations while preserving security-relevant events
- **Low overhead**: Uses eBPF for efficient kernel-space monitoring with minimal performance impact
- **Security focus**: Designed for detecting privilege escalation, sudo operations, and suspicious credential modifications
- **Multi-CPU support**: Efficiently handles events across all CPU cores

## Security Events Monitored

The tool captures and reports:
- Root privilege operations (UID/GID 0)
- `sudo` and `su` command executions
- SSH login sessions
- Password change operations (`passwd`)
- Any process involving credential modifications

Background system processes and kernel threads are automatically filtered out to focus on security-relevant activities.

## Prerequisites

- Linux kernel with eBPF support
- Rust nightly toolchain
- Root privileges (required for eBPF program loading)

### Installation

1. **Install Rust nightly and required components:**
   ```bash
   rustup toolchain install nightly
   rustup component add rust-src --toolchain nightly
   ```

2. **Install bpf-linker:**
   ```bash
   cargo install bpf-linker
   ```

3. **Clone and build:**
   ```bash
   git clone <repository-url>
   cd bpftoy
   ./build.sh
   ```

## Usage

Run the credential monitor with root privileges:

```bash
sudo ./target/release/bpftoy
```

The tool will display credential events in real-time:

```
Found program: kprobe
Successfully attached to commit_creds
Task credential tracer is running. Press Ctrl-C to exit.
[COMMIT_CREDS] Process: sudo (PID: 12345, TGID: 12345) - UID: 0, GID: 0, EUID: 0, EGID: 0
[COMMIT_CREDS] Process: su (PID: 12346, TGID: 12346) - UID: 1000, GID: 1000, EUID: 0, EGID: 0
```

### Testing the Monitor

To verify the tool is working, try these commands in another terminal:

```bash
sudo whoami                    # Should trigger credential event
sudo -u nobody whoami         # Should show credential change
sudo su -                     # Should show privilege escalation
```

## Output Format

Each event shows:
- **Event Type**: `COMMIT_CREDS` (when credentials are applied)
- **Process**: Command name that triggered the credential change
- **PID/TGID**: Process and thread group identifiers
- **UID/GID**: User and group IDs after the change
- **EUID/EGID**: Effective user and group IDs

## Debugging and Troubleshooting

### View Loaded eBPF Programs
```bash
sudo bpftool prog list
sudo bpftool prog list type kprobe
```

### Common Issues

**Permission denied**: Ensure you're running with `sudo`

**Build failures**: Verify nightly Rust and `bpf-linker` are installed

**No events shown**: The filtering may be working correctly - try `sudo whoami` to generate a test event

**Can't exit with Ctrl+C**: Use `sudo pkill bpftoy` or `sudo killall -9 bpftoy`

## Architecture

bpftoy consists of two main components:

1. **eBPF Kernel Program** (`bpftoy-ebpf/`): Runs in kernel space, hooks the `commit_creds` function, and captures credential events
2. **Userspace Program** (`src/`): Loads the eBPF program, receives events via perf buffers, and displays filtered results

The components communicate through a perf event array, allowing efficient transfer of credential event data from kernel to userspace.

## Use Cases

- **Security Research**: Monitor privilege escalation techniques and credential abuse
- **Incident Response**: Track suspicious credential changes during investigations
- **System Monitoring**: Observe legitimate administrative activities
- **Malware Analysis**: Detect credential manipulation by malicious software

## Contributing

This tool is designed for defensive security research purposes. When contributing:

- Focus on security monitoring and detection capabilities
- Ensure efficient filtering to minimize false positives
- Test thoroughly in controlled environments
- Document any new filtering criteria or detection logic

## Disclaimer

This tool is intended for authorized security research and system monitoring only. Users are responsible for complying with applicable laws and regulations when using this software.
