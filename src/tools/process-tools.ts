/**
 * Process management MCP tools for Frida
 */

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getDevice, withTimeout } from '../helpers.js';
import { logger } from '../logger.js';

/**
 * Register process management tools with the MCP server
 */
export function registerProcessTools(server: McpServer): void {
    
    // Spawn Process
    server.registerTool(
        'spawn_process',
        {
            title: 'Spawn Process',
            description: 'Spawn a process with Frida attached in paused state. The process will be paused at startup. Use resume_process() after loading scripts to continue execution.',
            inputSchema: {
                program: z.string().describe('Path to executable to spawn'),
                args: z.array(z.string()).optional().describe('Optional command-line arguments'),
                device_id: z.string().optional().describe('Optional device ID')
            },
            outputSchema: {
                pid: z.number().optional(),
                success: z.boolean(),
                program: z.string().optional(),
                message: z.string().optional(),
                error: z.string().optional()
            }
        },
        async ({ program, args, device_id }: { program: string; args?: string[]; device_id?: string }) => {
            try {
                const device = await getDevice(device_id);
                // Frida's spawn() expects argv as an array: [program, arg1, arg2, ...]
                const argv = [program, ...(args || [])];
                const pid = await device.spawn(argv);
                logger.info(`Spawned process: ${program} (PID: ${pid})`);
                
                const result = {
                    pid,
                    success: true,
                    program,
                    message: `Process spawned (PID: ${pid}), use resume_process`
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            } catch (error) {
                const result = {
                    success: false,
                    error: `Failed to spawn ${program}: ${error instanceof Error ? error.message : String(error)}`
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            }
        }
    );
    
    // Resume Process
    server.registerTool(
        'resume_process',
        {
            title: 'Resume Process',
            description: 'Resume a spawned process.',
            inputSchema: {
                pid: z.number().describe('Process ID to resume'),
                device_id: z.string().optional().describe('Optional device ID')
            },
            outputSchema: {
                success: z.boolean(),
                pid: z.number(),
                message: z.string().optional(),
                error: z.string().optional()
            }
        },
        async ({ pid, device_id }: { pid: number; device_id?: string }) => {
            try {
                const device = await getDevice(device_id);
                await device.resume(pid);
                
                const result = {
                    success: true,
                    pid,
                    message: `Process ${pid} resumed`
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            } catch (error) {
                const result = {
                    success: false,
                    pid,
                    error: `Failed to resume process ${pid}: ${error instanceof Error ? error.message : String(error)}`
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            }
        }
    );
    
    // Kill Process
    server.registerTool(
        'kill_process',
        {
            title: 'Kill Process',
            description: 'Kill a process by PID.',
            inputSchema: {
                pid: z.number().describe('Process ID to kill'),
                device_id: z.string().optional().describe('Optional device ID')
            },
            outputSchema: {
                success: z.boolean(),
                pid: z.number(),
                message: z.string().optional(),
                error: z.string().optional()
            }
        },
        async ({ pid, device_id }: { pid: number; device_id?: string }) => {
            try {
                const device = await getDevice(device_id);
                
                // Wrap kill operation with 30-second timeout (matching Python implementation)
                await withTimeout(
                    device.kill(pid),
                    30000,
                    `Kill operation for PID ${pid}`
                );
                
                const result = {
                    success: true,
                    pid,
                    message: `Process ${pid} killed`
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            } catch (error) {
                const result = {
                    success: false,
                    pid,
                    error: `Failed to kill process: ${error instanceof Error ? error.message : String(error)}`
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            }
        }
    );
}