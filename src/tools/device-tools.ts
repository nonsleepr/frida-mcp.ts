/**
 * Device-related MCP tools for Frida
 */

import * as frida from 'frida';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getDevice } from '../helpers.js';
import type { FridaDevice, FridaProcess } from '../types.js';

/**
 * Register device-related tools with the MCP server
 */
export function registerDeviceTools(server: McpServer): void {
    
    // Enumerate Devices
    server.registerTool(
        'enumerate_devices',
        {
            title: 'Enumerate Devices',
            description: 'List all connected Frida devices. Returns list of devices with their IDs, names, and types. Useful for discovering available devices before attaching.',
            inputSchema: {},
            outputSchema: {
                devices: z.array(z.object({
                    id: z.string(),
                    name: z.string(),
                    type: z.string()
                }))
            }
        },
        async () => {
            const devices = await frida.enumerateDevices();
            const deviceList: FridaDevice[] = devices.map(device => ({
                id: device.id,
                name: device.name,
                type: device.type
            }));
            
            return {
                content: [{ type: 'text', text: JSON.stringify(deviceList, null, 2) }],
                structuredContent: { devices: deviceList }
            };
        }
    );
    
    // Get Device Info
    server.registerTool(
        'get_device_info',
        {
            title: 'Get Device Info',
            description: 'Get detailed information about a specific device by ID.',
            inputSchema: {
                device_id: z.string().describe('The device ID to query')
            },
            outputSchema: {
                id: z.string(),
                name: z.string(),
                type: z.string(),
                error: z.string().optional()
            }
        },
        async ({ device_id }: { device_id: string }) => {
            try {
                const device = await frida.getDevice(device_id);
                const result = {
                    id: device.id,
                    name: device.name,
                    type: device.type
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            } catch (error) {
                const result = {
                    error: `Device with ID ${device_id} not found`,
                    id: device_id,
                    name: '',
                    type: ''
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            }
        }
    );
    
    // Enumerate Processes
    server.registerTool(
        'enumerate_processes',
        {
            title: 'Enumerate Processes',
            description: 'List all processes on a device.',
            inputSchema: {
                device_id: z.string().optional().describe('Optional device ID (uses default device if not specified)')
            },
            outputSchema: {
                processes: z.array(z.object({
                    pid: z.number(),
                    name: z.string()
                }))
            }
        },
        async ({ device_id }: { device_id?: string }) => {
            const device = await getDevice(device_id);
            const processes = await device.enumerateProcesses();
            const processList: FridaProcess[] = processes.map(proc => ({
                pid: proc.pid,
                name: proc.name
            }));
            
            return {
                content: [{ type: 'text', text: JSON.stringify(processList, null, 2) }],
                structuredContent: { processes: processList }
            };
        }
    );
    
    // Get Process by Name
    server.registerTool(
        'get_process_by_name',
        {
            title: 'Get Process by Name',
            description: 'Find a process by name (case-insensitive partial match).',
            inputSchema: {
                name: z.string().describe('Process name to search for (partial match supported)'),
                device_id: z.string().optional().describe('Optional device ID')
            },
            outputSchema: {
                pid: z.number().optional(),
                name: z.string().optional(),
                found: z.boolean(),
                error: z.string().optional()
            }
        },
        async ({ name, device_id }: { name: string; device_id?: string }) => {
            const device = await getDevice(device_id);
            const processes = await device.enumerateProcesses();
            
            for (const proc of processes) {
                if (proc.name.toLowerCase().includes(name.toLowerCase())) {
                    const result = {
                        pid: proc.pid,
                        name: proc.name,
                        found: true
                    };
                    
                    return {
                        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                        structuredContent: result
                    };
                }
            }
            
            const result = {
                found: false,
                error: `Process '${name}' not found`
            };
            
            return {
                content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                structuredContent: result
            };
        }
    );
    
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