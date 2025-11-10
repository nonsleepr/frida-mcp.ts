
/**
 * File operations MCP tools for Frida
 */

import * as frida from 'frida';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getDevice, executeScriptAndWait, sleep } from '../helpers.js';
import { SCRIPT_GET_MODULE_PATH, SCRIPT_READ_FILE_CHUNKS } from '../scripts.js';

/**
 * Register file operations tools with the MCP server
 */
export function registerFileTools(server: McpServer): void {
    
    // Download File
    server.registerTool(
        'download_file',
        {
            title: 'Download File',
            description: 'Download a file from remote system using Frida instrumentation. Uses double backslashes for Windows paths. Attaches to specified PID or finds explorer.exe. Works best for files up to ~500MB with 60s timeout.',
            inputSchema: {
                file_path: z.string().describe('Remote file path (use double backslashes on Windows)'),
                output_path: z.string().describe('Local output path'),
                pid: z.number().optional().describe('Optional PID to attach to (finds explorer.exe if not specified)'),
                device_id: z.string().optional().describe('Optional device ID or connection string (hostname:port or hostname)')
            },
            outputSchema: {
                status: z.string(),
                remote_path: z.string().optional(),
                local_path: z.string().optional(),
                size_bytes: z.number().optional(),
                chunks: z.number().optional(),
                message: z.string().optional(),
                error: z.string().optional()
            }
        },
        async ({ file_path, output_path, pid, device_id }: {
            file_path: string;
            output_path: string;
            pid?: number;
            device_id?: string;
        }) => {
            try {
                const device = await getDevice(device_id);
                
                let targetPid: number;
                
                // If PID specified, use it directly
                if (pid) {
                    targetPid = pid;
                } else {
                    // Try to attach to a system process
                    const processes = await device.enumerateProcesses();
                    if (processes.length === 0) {
                        const result = {
                            status: 'error',
                            error: 'No processes available to attach'
                        };
                        
                        return {
                            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                            structuredContent: result
                        };
                    }
                    
                    let foundPid: number | null = null;
                    for (const proc of processes) {
                        if (proc.name.toLowerCase() === 'explorer.exe') {
                            foundPid = proc.pid;
                            break;
                        }
                    }
                    
                    if (!foundPid) {
                        const result = {
                            status: 'error',
                            error: 'Could not find suitable process. Try specifying a PID with \'pid\' parameter.'
                        };
                        
                        return {
                            content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                            structuredContent: result
                        };
                    }
                    
                    targetPid = foundPid;
                }
                
                const session = await device.attach(targetPid);
                
                // Use script template for file reading
                const scriptCode = SCRIPT_READ_FILE_CHUNKS.replace('{path}', JSON.stringify(file_path));
                
                const script = await session.createScript(scriptCode);
                
                // Setup streaming file write
                const path = await import('path');
                const fs = await import('fs/promises');
                const fsSync = await import('fs');
                const outputFile = path.join(process.cwd(), output_path);
                const dirname = path.dirname(outputFile);
                if (dirname) {
                    await fs.mkdir(dirname, { recursive: true });
                }
                
                // Create write stream for efficient memory usage
                const writeStream = fsSync.createWriteStream(outputFile);
                
                let totalBytes = 0;
                let chunkCount = 0;
                let fileData: any = null;
                let streamError: Error | null = null;
                
                // Handle stream errors
                writeStream.on('error', (error) => {
                    streamError = error;
                });
                
                script.message.connect((message: frida.Message, data: Buffer | null) => {
                    if (message.type === 'send') {
                        const payload = message.payload;
                        if (payload.type === 'chunk' && data) {
                            // Stream chunk directly to disk - no memory accumulation
                            writeStream.write(data);
                            totalBytes += data.length;
                            chunkCount++;
                        } else if (payload.type === 'complete') {
                            writeStream.end();
                            fileData = payload;
                        } else if (payload.type === 'error') {
                            writeStream.end();
                            fileData = payload;
                        }
                    }
                });
                
                await script.load();
                
                // Wait for file transfer completion (max 60 seconds)
                const maxWait = 60000;
                const startTime = Date.now();
                while (fileData === null && (Date.now() - startTime) < maxWait && !streamError) {
                    await sleep(500);
                }
                
                await script.unload();
                await session.detach();
                
                // Check for stream errors
                if (streamError) {
                    const result = {
                        status: 'error',
                        error: `File write error: ${streamError.message}`
                    };
                    
                    return {
                        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                        structuredContent: result
                    };
                }
                
                if (fileData === null) {
                    const result = {
                        status: 'error',
                        error: 'Timeout waiting for file download'
                    };
                    
                    return {
                        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                        structuredContent: result
                    };
                }
                
                if (fileData.status === 'error') {
                    return {
                        content: [{ type: 'text', text: JSON.stringify(fileData, null, 2) }],
                        structuredContent: fileData
                    };
                }
                
                const result = {
                    status: 'success',
                    remote_path: file_path,
                    local_path: outputFile,
                    size_bytes: totalBytes,
                    chunks: chunkCount,
                    message: `Successfully streamed ${totalBytes} bytes in ${chunkCount} chunks`
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
                
            } catch (error) {
                const result = {
                    status: 'error',
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