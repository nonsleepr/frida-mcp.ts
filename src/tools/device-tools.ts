/**
 * Device-related MCP tools for Frida
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';

/**
 * Register device-related tools with the MCP server
 */
export function registerDeviceTools(server: McpServer): void {
    // Currently no device-specific tools registered
    // Device operations are handled through:
    // - Resources: frida://devices, frida://devices/{device_id}
    // - Session tools: create_interactive_session
}