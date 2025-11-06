/**
 * Device-related MCP tools for Frida
 */

import * as frida from 'frida';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getDevice } from '../helpers.js';

/**
 * Register device-related tools with the MCP server
 */
export function registerDeviceTools(server: McpServer): void {
    
    // Attach to Process
    server.registerTool(
        'attach_to_process',
        {
            title: 'Attach to Process',
            description: 'Attach to a running process by PID. Returns attachment status without creating a persistent session. Use create_interactive_session for session-based instrumentation.',
            inputSchema: {
                pid: z.number().describe('Process ID to attach to'),
                device_id: z.string().optional().describe('Optional device ID')
            },
            outputSchema: {
                pid: z.number(),
                success: z.boolean(),
                is_detached: z.boolean(),
                message: z.string().optional(),
                error: z.string().optional()
            }
        },
        async ({ pid, device_id }: { pid: number; device_id?: string }) => {
            try {
                const device = await getDevice(device_id);
                const session = await device.attach(pid);
                
                // Immediately detach - this matches Python's simple attachment behavior
                await session.detach();
                
                const result = {
                    pid,
                    success: true,
                    is_detached: true,
                    message: `Successfully attached to and detached from process ${pid}. Use create_interactive_session for persistent sessions.`
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            } catch (error) {
                const result = {
                    pid,
                    success: false,
                    is_detached: false,
                    error: error instanceof Error ? error.message : String(error)
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            }
        }
    );
}