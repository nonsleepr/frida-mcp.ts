
# Frida MCP Server

A MCP server that provides dynamic instrumentation capabilities through Frida. Built with TypeScript and optimized for Bun runtime.

## Features

- **Dynamic Instrumentation**: Hook functions, inspect memory, and modify behavior of running processes
- **Device Management**: Support for local, USB, and remote Frida devices
- **Process Control**: Spawn, attach, resume, and kill processes
- **Interactive Sessions**: Create persistent sessions for complex instrumentation workflows
- **Script Execution**: Execute JavaScript code with both one-shot and persistent modes
- **File Operations**: Download files from instrumented processes and query module information

## Prerequisites

- [Bun](https://bun.sh/) >= 1.0.0
- [Frida](https://frida.re/) >= 17.0.0 (installed on target system)

## Installation

No installation required! Use `npx` to run directly from GitHub (see Configuration below).

For local development:
```bash
# Clone the repository
git clone https://github.com/nonsleepr/frida-mcp.ts
cd frida-mcp.ts

# Install dependencies
bun install
```

**Note:** While this project is built with Bun, `npx` (from npm) is required to run from GitHub due to native dependency requirements. Use `npx --yes github:nonsleepr/frida-mcp.ts` to run the server.

## Configuration

### Environment Variables

- `FRIDA_DEFAULT_DEVICE`: Default remote device connection string (e.g., "192.168.1.100:27042" or "192.168.1.100", port defaults to 27042)

### Claude Desktop Configuration

Add to your Claude Desktop config file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "frida": {
      "command": "npx",
      "args": ["--yes", "github:nonsleepr/frida-mcp.ts"],
      "env": {
        "FRIDA_DEFAULT_DEVICE": "192.168.1.100:27042"
      }
    }
  }
}
```

### Roo Configuration

Add this to your project's `.roo/mcp.json`:

```json
{
  "mcpServers": {
    "frida": {
      "command": "npx",
      "args": ["--yes", "github:nonsleepr/frida-mcp.ts"],
      "env": {
        "FRIDA_DEFAULT_DEVICE": "10.254.1.69:27042"
      },
      "disabled": false,
      "alwaysAllow": []
    }
  }
}
```

**Note**: Set `FRIDA_DEFAULT_DEVICE` to your Frida server's connection string (hostname:port or just hostname), or leave it empty to use local devices.

## Available Tools

### Device & Process Management

| Tool | Description | Parameters |
|------|-------------|------------|
| `attach_to_process` | Attach to a running process by PID. Returns attachment status without creating a persistent session. Use `create_interactive_session` for session-based instrumentation. | `pid` (number)<br>`device_id` (optional: "default", "local", "usb", "remote", device ID, or connection string hostname:port) |
| `spawn_process` | Spawn a process with Frida attached in paused state. The process will be paused at startup. Use `resume_process()` after loading scripts to continue execution. | `program` (string)<br>`args` (optional string[])<br>`device_id` (optional: "default" or connection string) |
| `resume_process` | Resume a spawned process. | `pid` (number)<br>`device_id` (optional: "default" or connection string) |
| `kill_process` | Kill a process by PID. | `pid` (number)<br>`device_id` (optional: "default" or connection string) |

### Interactive Sessions

| Tool | Description | Parameters |
|------|-------------|------------|
| `create_interactive_session` | Create an interactive session for dynamic instrumentation. Establishes a Frida session for injecting JavaScript, hooking functions, and monitoring the target process. The session persists until explicitly closed or the process terminates. | `process_id` (number)<br>`device_id` (optional: "default" or connection string) |
| `execute_in_session` | Execute JavaScript code within an existing Frida session.<br><br>**Modes:**<br>• `keep_alive=false` (default): Script runs once, results in initial_logs<br>• `keep_alive=true`: Script persists for hooks, retrieve messages via `frida://sessions/{session_id}/messages` resource | `session_id` (string)<br>`javascript_code` (string)<br>`keep_alive` (optional boolean, default: false) |
| `load_script_file` | Load and execute a Frida JavaScript file into an existing session. | `session_id` (string)<br>`script_path` (string)<br>`keep_alive` (optional boolean, default: true) |

### File Operations

| Tool | Description | Parameters |
|------|-------------|------------|
| `download_file` | Download a file from remote system using Frida instrumentation. Uses double backslashes for Windows paths. Attaches to specified PID or finds explorer.exe. Works best for files up to ~500MB with 60s timeout. | `file_path` (string)<br>`output_path` (string)<br>`pid` (optional number)<br>`device_id` (optional: "default" or connection string) |

## Available Resources

Resources provide real-time, read-only access to Frida state via URI.

### Direct Resources

| URI | Description |
|-----|-------------|
| `frida://devices` | List all connected Frida devices |
| `frida://sessions` | List all active Frida sessions and their statuses |

### Resource Templates

| URI Template | Description |
|--------------|-------------|
| `frida://devices/{device_id}` | Get detailed information about a specific device by ID |
| `frida://devices/{device_id}/processes` | List processes on a specific Frida device. Use "default", "local", "usb", or "remote" for automatic device selection, provide a specific device ID, or use a connection string (hostname:port or hostname). |
| `frida://devices/{device_id}/processes/by-name/{process_name}` | Find a process by name (case-insensitive partial match) on a specific device. Use "default" for configured remote device. Supports connection strings (hostname:port or hostname). |
| `frida://devices/{device_id}/processes/{pid}/module` | Get main module information for a process (path, base address, size). Use "default" for configured remote device. Supports connection strings (hostname:port or hostname). |
| `frida://sessions/{sessionId}/messages` | Retrieve messages from persistent scripts with default 100 message limit. Messages are consumed when retrieved. |
| `frida://sessions/{sessionId}/messages/{limit}` | Retrieve messages from persistent scripts with custom limit. Use `/last:N` (e.g., `/last:10` for last 10 messages) or `/all` for unlimited. Messages are consumed when retrieved. |
