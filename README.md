# Frida MCP Server

A Modern Context Protocol (MCP) server that provides dynamic instrumentation capabilities through Frida. Built with TypeScript and optimized for Bun runtime.

## Features

- **Dynamic Instrumentation**: Hook functions, inspect memory, and modify behavior of running processes
- **Device Management**: Support for local, USB, and remote Frida devices
- **Process Control**: Spawn, attach, resume, and kill processes
- **Interactive Sessions**: Create persistent sessions for complex instrumentation workflows
- **File Operations**: Download files from instrumented processes
- **MCP Resources**: Real-time access to devices, processes, and session information

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

### HTTP Mode (Coming Soon)

```bash
bun run start:http
```

### SSE Mode (Coming Soon)

```bash
bun run start:sse
```

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

- `enumerate_devices`: List all connected Frida devices
- `get_device_info`: Get detailed information about a specific device
- `enumerate_processes`: List all processes on a device
- `get_process_by_name`: Find a process by name (supports partial matching)
- `attach_to_process`: Test attachment to a running process

### Process Tools

- `spawn_process`: Spawn a new process with Frida attached
- `resume_process`: Resume a spawned process
- `kill_process`: Terminate a process

### Session Tools

- `create_interactive_session`: Create a persistent instrumentation session
- `execute_in_session`: Execute JavaScript code in an active session
- `load_script_file`: Load and execute a Frida script from a file
- `get_session_messages`: Retrieve messages from persistent scripts (also available as resource)

### File Tools

- `get_process_module_path`: Get information about a process's main module
- `download_file`: Download files from a remote system via instrumentation

## Available Resources

- `frida://version`: Frida version information
- `frida://devices`: List of connected devices
- `frida://processes`: List of processes on default device
- `frida://sessions`: Active instrumentation sessions
- `frida://sessions/{sessionId}/messages`: Retrieve messages from persistent scripts

## Example Workflows

### Basic Process Instrumentation

```javascript
// 1. List processes
enumerate_processes()

// 2. Find target process
get_process_by_name({ name: "myapp" })

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
// Access resource: frida://sessions/session_1234_.../messages
```

### Remote Device Instrumentation

```bash
# Set environment variables
export FRIDA_REMOTE_HOST=192.168.1.100
export FRIDA_REMOTE_PORT=27042

# Start server
bun run start
```

## Development

### Project Structure

```
frida-mcp-server/
├── src/
│   ├── index.ts              # Main entry point
│   ├── types.ts              # TypeScript type definitions
│   ├── logger.ts             # Logging utility
│   ├── state.ts              # Global state management
│   ├── scripts.ts            # Frida script templates
│   ├── helpers.ts            # Helper functions
│   ├── resources.ts          # MCP resource registration
│   └── tools/
│       ├── device-tools.ts   # Device management tools
│       ├── process-tools.ts  # Process control tools
│       ├── session-tools.ts  # Session management tools
│       └── file-tools.ts     # File operation tools
├── package.json
├── tsconfig.json
├── .gitignore
└── README.md
```

### Type Checking

```bash
bun run type-check
```

### Building

```bash
bun run build
```

## Troubleshooting

### TypeScript Errors During Development

The TypeScript errors you see during development are expected until dependencies are installed:

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

### Process Attachment Failures

Common causes:
- Process doesn't exist or has terminated
- Insufficient permissions (may need root/administrator)
- Anti-debugging protections in target process

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## License

MIT

## Implementation Notes

### Python vs TypeScript Behavioral Differences

This TypeScript implementation maintains functional parity with the Python reference implementation (`frida-mcp.py`) with the following architectural differences:

#### Message Queue Implementation
- **Python**: Uses thread-safe `asyncio.Queue` with event loop integration
- **TypeScript**: Uses array-based queue (suitable for single-threaded JavaScript runtime)
- **Impact**: Both implementations are functionally equivalent for their respective runtimes

#### Tool Behavior Alignment

All tools now match Python behavior:

1. **`attach_to_process()`**: Simple attachment that immediately detaches (matches Python)
   - Returns `{pid, success, is_detached}` status
   - Use `create_interactive_session()` for persistent sessions

2. **`kill_process()`**: Includes 30-second timeout protection (matches Python)
   - Prevents hanging on unresponsive processes
   - Returns timeout error if operation exceeds limit

3. **`load_script_file()`**: Fully implemented (matches Python)
   - Reads JavaScript files from filesystem
   - Executes with same wrapper as `execute_in_session()`
   - Supports both `keep_alive` modes

4. **`get_session_messages()`**: Available as both tool and resource (matches Python)
   - Tool: `get_session_messages(session_id, max_messages?)`
   - Resource: `frida://sessions/{sessionId}/messages`
   - Messages are consumed (removed from queue) when retrieved

#### Device Selection Priority

Both implementations use identical device selection logic:
1. Explicit `device_id` parameter (if provided)
2. `FRIDA_REMOTE_HOST` environment variable (for remote debugging)
3. USB device (for mobile device debugging)
4. Local device (fallback for local process instrumentation)

#### Script Execution Modes

Both implementations support two execution modes:

- **One-shot mode** (`keep_alive=false`): Script executes once and unloads
  - Use for queries and one-time operations
  - Returns immediate results in response

- **Persistent mode** (`keep_alive=true`): Script remains loaded for continuous monitoring
  - Use for hooks and continuous instrumentation
  - Retrieve messages via `get_session_messages()` tool or resource

### Timeout Protection

The following operations include timeout protection:
- `kill_process()`: 30-second timeout (matches Python)
- `download_file()`: 60-second timeout for file operations

## Related Projects

- [Frida](https://frida.re/) - Dynamic instrumentation toolkit
- [Model Context Protocol](https://modelcontextprotocol.io/) - Protocol for AI-tool integration
- [Claude Desktop](https://claude.ai/) - AI assistant with MCP support
- [Roo](https://roo.cline.bot/) - AI coding assistant with MCP support