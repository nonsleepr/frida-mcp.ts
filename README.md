
# Frida MCP Server

A Model Context Protocol (MCP) server that provides dynamic instrumentation capabilities through Frida. Built with TypeScript and optimized for Bun runtime.

## Features

- **Dynamic Instrumentation**: Hook functions, inspect memory, and modify behavior of running processes
- **Device Management**: Support for local, USB, and remote Frida devices
- **Process Control**: Spawn, attach, resume, and kill processes
- **Interactive Sessions**: Create persistent sessions for complex instrumentation workflows
- **Script Execution**: Execute JavaScript code with both one-shot and persistent modes
- **File Operations**: Download files from instrumented processes and query module information
- **MCP Resources**: Real-time access to devices, processes, sessions, and script messages

## Prerequisites

- [Bun](https://bun.sh/) >= 1.0.0
- [Frida](https://frida.re/) >= 17.0.0 (installed on target system)

## Installation

```bash
# Clone the repository
git clone <repository-url>
cd frida-mcp-server

# Install dependencies
bun install
```

## Usage

### Stdio Mode (Default)

For use with Claude Desktop, Roo, or other MCP clients:

```bash
bun run start
```

### Development Mode with Watch

```bash
bun run dev
```

### HTTP and SSE Modes

HTTP (streamable-http) and SSE transport modes are not yet implemented. Currently, only stdio mode is supported.

## Configuration

### Environment Variables

- `FRIDA_REMOTE_HOST`: Remote Frida server hostname/IP (e.g., "192.168.1.100")
- `FRIDA_REMOTE_PORT`: Remote Frida server port (default: 27042)

### Claude Desktop Configuration

Add to your Claude Desktop config file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`  
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "frida": {
      "command": "bun",
      "args": ["run", "/path/to/frida-mcp-server/src/index.ts"]
    }
  }
}
```

### Roo Configuration

This project includes a pre-configured `.roo/mcp.json` file for project-level MCP server configuration. The configuration is automatically available when you open this project in VS Code with Roo installed.

**Project Configuration (`.roo/mcp.json`):**
```json
{
  "mcpServers": {
    "frida": {
      "command": "bun",
      "args": ["run", "src/index.ts"],
      "env": {
        "FRIDA_REMOTE_HOST": "",
        "FRIDA_REMOTE_PORT": "27042"
      },
      "disabled": false,
      "alwaysAllow": []
    }
  }
}
```

**Benefits of Project-Level Configuration:**
- ✅ Automatically available when opening the project
- ✅ Can be committed to version control for team sharing
- ✅ No need to manually configure in VS Code settings
- ✅ Environment variables can be customized per project

**To use with a remote Frida device:**
Edit `.roo/mcp.json` and set the `FRIDA_REMOTE_HOST` environment variable:
```json
"env": {
  "FRIDA_REMOTE_HOST": "192.168.1.100",
  "FRIDA_REMOTE_PORT": "27042"
}
```

## Available Tools

### Device Tools

- **`attach_to_process`**: Test attachment to a running process
  - Parameters: `pid` (number), `device_id` (optional string)
  - Returns: Attachment status (immediately detaches)
  - Note: For persistent sessions, use `create_interactive_session`

### Process Tools

- **`spawn_process`**: Spawn a new process with Frida attached
  - Parameters: `program` (string), `args` (optional string[]), `device_id` (optional string)
  - Returns: PID of spawned process
  - Note: Process spawns in paused state; use `resume_process` to continue execution

- **`resume_process`**: Resume a spawned process
  - Parameters: `pid` (number), `device_id` (optional string)
  - Returns: Success status

- **`kill_process`**: Terminate a process
  - Parameters: `pid` (number), `device_id` (optional string)
  - Returns: Success status
  - Note: Includes 30-second timeout protection

### Session Tools

- **`create_interactive_session`**: Create a persistent instrumentation session
  - Parameters: `process_id` (number), `device_id` (optional string)
  - Returns: `session_id` for use with other session commands
  - Use case: Establishes a session for injecting JavaScript and monitoring the process

- **`execute_in_session`**: Execute JavaScript code in an active session
  - Parameters: `session_id` (string), `javascript_code` (string), `keep_alive` (optional boolean, default: false)
  - Returns: Execution results, initial logs, and errors if any
  - Modes:
    - `keep_alive=false`: Script runs once and unloads (for queries)
    - `keep_alive=true`: Script persists for continuous monitoring (retrieve messages via resource)

- **`load_script_file`**: Load and execute a Frida script from a file
  - Parameters: `session_id` (string), `script_path` (string), `keep_alive` (optional boolean, default: true)
  - Returns: Execution results with file path reference
  - Note: Reads JavaScript files from filesystem and executes them

### File Tools

- **`download_file`**: Download files from a remote system via instrumentation
  - Parameters: `file_path` (string), `output_path` (string), `pid` (optional number), `device_id` (optional string)
  - Returns: File size, chunk count, and local path
  - Note: Uses double backslashes for Windows paths; works best for files up to ~500MB with 60s timeout

## Available Resources

Resources provide real-time, read-only access to Frida state via URI. Resources use URI templates for parameterized access.

### Static Resources

- **`frida://devices`**: List of all connected devices with IDs, names, and types
- **`frida://sessions`**: Active instrumentation sessions with detailed status (script count, pending messages, etc.)

### Resource Templates

- **`frida://devices/{device_id}`**: Get detailed information about a specific device
  - Examples:
    - `frida://devices/local` - Local device info
    - `frida://devices/usb` - USB device info
    - `frida://devices/{specific-device-id}` - Info for specific device by ID

- **`frida://devices/{device_id}/processes`**: List processes on a specific device
  - Examples:
    - `frida://devices/local/processes` - Local device processes
    - `frida://devices/usb/processes` - USB device processes
    - `frida://devices/remote/processes` - Remote device processes (uses `FRIDA_REMOTE_HOST` env var)
    - `frida://devices/{specific-device-id}/processes` - Processes on a specific device by ID

- **`frida://devices/{device_id}/processes/by-name/{process_name}`**: Find a process by name (case-insensitive partial match)
  - Examples:
    - `frida://devices/local/processes/by-name/chrome` - Find Chrome on local device
    - `frida://devices/usb/processes/by-name/Calculator` - Find Calculator on USB device
  - Note: Returns first matching process

- **`frida://devices/{device_id}/processes/{pid}/module`**: Get main module information for a process
  - Examples:
    - `frida://devices/local/processes/1234/module` - Main module for PID 1234 on local device
    - `frida://devices/usb/processes/5678/module` - Main module for PID 5678 on USB device
  - Returns: Module name, path, base address, and size

- **`frida://sessions/{sessionId}/messages[/last:N or /all]`**: Retrieve messages from persistent scripts
  - Default limit: 100 messages
  - Examples:
    - `frida://sessions/session_1234_5678/messages` - Last 100 messages (default)
    - `frida://sessions/session_1234_5678/messages/last:10` - Last 10 messages
    - `frida://sessions/session_1234_5678/messages/last:1` - Most recent message only
    - `frida://sessions/session_1234_5678/messages/all` - All messages (no limit)
  - Note: Messages are consumed (removed from queue) when retrieved

## Example Workflows

### Basic Process Instrumentation

```javascript
// 1. List processes on local device
// Access resource: frida://devices/local/processes

// 2. Find target process
// Access resource: frida://devices/local/processes/by-name/myapp

// 3. Create session
create_interactive_session({ process_id: 1234 })

// 4. Execute instrumentation code
execute_in_session({
  session_id: "session_1234_...",
  javascript_code: `
    console.log("Intercepting functions...");
    Interceptor.attach(Module.findExportByName(null, "open"), {
      onEnter: function(args) {
        console.log("open() called with:", Memory.readUtf8String(args[0]));
      }
    });
  `,
  keep_alive: true
})

// 5. Retrieve messages
// Access resource: frida://sessions/session_1234_.../messages/last:10
```

### Spawning and Instrumenting a Process

```javascript
// 1. Spawn process in paused state
spawn_process({ 
  program: "/path/to/app",
  args: ["--debug"]
})

// 2. Create session for the spawned process
create_interactive_session({ process_id: 5678 })

// 3. Load instrumentation script
execute_in_session({
  session_id: "session_5678_...",
  javascript_code: `
    // Hook before process starts
    Interceptor.attach(Module.findExportByName(null, "malloc"), {
      onEnter: function(args) {
        console.log("malloc size:", args[0].toInt32());
      }
    });
  `,
  keep_alive: true
})

// 4. Resume process execution
resume_process({ pid: 5678 })

// 5. Monitor messages
// Access resource: frida://sessions/session_5678_.../messages
```

### Remote Device Instrumentation

```bash
# Set environment variables
export FRIDA_REMOTE_HOST=192.168.1.100
export FRIDA_REMOTE_PORT=27042

# Start server
bun run start
```

Then access remote device processes via resource:
```
frida://devices/remote/processes
```

Tools will also automatically connect to the remote device when device_id is not specified.

### File Download from Remote System

```javascript
// 1. Find target process (or specify PID directly)
get_process_by_name({ name: "explorer" })

// 2. Download file
download_file({
  file_path: "C:\\\\Windows\\\\System32\\\\notepad.exe",
  output_path: "./downloaded_notepad.exe",
  pid: 1234  // Optional, will find explorer.exe if not specified
})
```

## Development

### Project Structure

```
frida-mcp-server/
├── src/
│   ├── index.ts              # Main entry point and server initialization
│   ├── types.ts              # TypeScript type definitions
│   ├── logger.ts             # Logging utility
│   ├── state.ts              # Global state management (sessions, scripts, messages)
│   ├── scripts.ts            # Frida script templates
│   ├── helpers.ts            # Helper functions (device selection, script execution)
│   ├── resources.ts          # MCP resource registration
│   └── tools/
│       ├── device-tools.ts   # Device management tools
│       ├── process-tools.ts  # Process control tools
│       ├── session-tools.ts  # Session management tools
│       └── file-tools.ts     # File operation tools
├── .roo/
│   └── mcp.json             # Roo MCP server configuration
├── package.json
├── tsconfig.json
├── .gitignore
└── README.md
```

### Key Components

- **State Management** ([`src/state.ts`](src/state.ts:1)): Manages active sessions, loaded scripts, and message queues
- **Device Selection** ([`src/helpers.ts`](src/helpers.ts:26)): Implements priority-based device selection (explicit ID → remote → USB → local)
- **Script Execution** ([`src/scripts.ts`](src/scripts.ts:40)): Provides templates for common Frida operations with console.log capture
- **Message Handling** ([`src/helpers.ts`](src/helpers.ts:126)): Async message retrieval with timeout protection

### Type Checking

```bash
bun run type-check
```

### Building

```bash
bun run build
```

## Architecture

### Device Selection Priority

The server uses the following priority order for device selection:

1. **Explicit `device_id` parameter** (if provided in tool call)
2. **`FRIDA_REMOTE_HOST` environment variable** (for remote debugging)
3. **USB device** (for mobile device debugging)
4. **Local device** (fallback for local process instrumentation)

This is implemented in [`getDevice()`](src/helpers.ts:26) helper function.

### Script Execution Modes

The server supports two execution modes for JavaScript code:

- **One-shot mode** (`keep_alive=false`): 
  - Script executes once and immediately unloads
  - Use for queries and one-time operations
  - Returns immediate results in response
  - Example: Reading memory, enumerating modules

- **Persistent mode** (`keep_alive=true`):
  - Script remains loaded for continuous monitoring
  - Use for hooks and continuous instrumentation
  - Retrieve messages via [`get_session_messages()`](src/tools/session-tools.ts:426) tool or [`frida://sessions/{sessionId}/messages`](src/resources.ts:140) resource
  - Example: Function hooking, event monitoring

### Message Queue Implementation

- Uses array-based queue (suitable for single-threaded JavaScript runtime)
- Messages are stored per session in [`scriptMessages`](src/state.ts:15) Map
- Messages are consumed (removed) when retrieved
- Supports timeout protection for message retrieval

### Timeout Protection

The following operations include timeout protection:

- [`kill_process()`](src/tools/process-tools.ts:115): 30-second timeout
- [`download_file()`](src/tools/file-tools.ts:86): 60-second timeout
- [`getSessionMessagesAsync()`](src/helpers.ts:126): Configurable timeout (default: 5 seconds)

## Troubleshooting

### TypeScript Errors During Development

TypeScript errors during development are expected until dependencies are installed:

```bash
bun install
```

### Frida Not Found

Ensure Frida is installed on your system:

```bash
# Check Frida installation
frida --version

# Install Frida (if needed)
pip install frida-tools
```

### Connection Issues

For remote devices:
1. Ensure `frida-server` is running on the target device
2. Verify network connectivity
3. Check firewall settings
4. Confirm the correct port (default: 27042)

### Process Attachment Failures

Common causes:
- Process doesn't exist or has terminated
- Insufficient permissions (may need root/administrator)
- Anti-debugging protections in target process
- Process is already being debugged by another tool

### Session Messages Not Appearing

If messages from persistent scripts aren't appearing:
1. Verify the script is loaded with `keep_alive=true`
2. Check that the script is using `send()` to emit messages
3. Ensure the session is still alive (check [`frida://sessions`](src/resources.ts:86) resource)
4. Try retrieving messages with [`get_session_messages()`](src/tools/session-tools.ts:426) tool

### File Download Issues

If file downloads fail:
1. Use double backslashes for Windows paths (e.g., `C:\\\\path\\\\to\\\\file`)
2. Ensure the file exists and is accessible
3. Check file size (works best for files up to ~500MB)
4. Verify sufficient permissions to read the file
5. Try specifying a PID explicitly if auto-detection fails

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

MIT

## Implementation Notes

### TypeScript Implementation

This TypeScript implementation maintains functional parity with Python reference implementations while leveraging TypeScript's type safety and Bun's performance characteristics.

#### Key Design Decisions

1. **Array-Based Message Queue**: Uses JavaScript arrays instead of async queues, suitable for single-threaded runtime
2. **Timeout Protection**: Implements Promise.race patterns for timeout handling
3. **Type Safety**: Comprehensive TypeScript types for all Frida objects and responses
4. **Modular Architecture**: Tools organized by functionality (device, process, session, file)

#### Tool Behavior

All tools match expected Frida