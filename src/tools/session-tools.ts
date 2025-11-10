
/**
 * Session management MCP tools for Frida
 */

import * as frida from 'frida';
import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getDevice, generateSessionId, sleep, cleanupSession } from '../helpers.js';
import { logger } from '../logger.js';
import { sessions, scripts, scriptMessages } from '../state.js';
import type { ScriptMessage } from '../types.js';

/**
 * Register session management tools with the MCP server
 */
export function registerSessionTools(server: McpServer): void {
    
    // Create Interactive Session
    server.registerTool(
        'create_interactive_session',
        {
            title: 'Create Interactive Session',
            description: 'Create an interactive session for dynamic instrumentation. Establishes a Frida session for injecting JavaScript, hooking functions, and monitoring the target process. The session persists until explicitly closed or the process terminates.',
            inputSchema: {
                process_id: z.number().describe('PID of target process'),
                device_id: z.string().optional().describe('Optional device ID or connection string (hostname:port or hostname)')
            },
            outputSchema: {
                status: z.string(),
                process_id: z.number().optional(),
                session_id: z.string().optional(),
                message: z.string().optional(),
                error: z.string().optional()
            }
        },
        async ({ process_id, device_id }: { process_id: number; device_id?: string }) => {
            try {
                logger.info(`Creating session for PID ${process_id}`);
                const device = await getDevice(device_id);
                const session = await device.attach(process_id);
                
                // Generate a unique session ID
                const sessionId = generateSessionId(process_id);
                logger.debug(`Generated session_id: ${sessionId}`);
                
                // Store the session
                sessions.set(sessionId, session);
                scripts.set(sessionId, []);
                scriptMessages.set(sessionId, []);
                
                // Setup session lifecycle management - auto-cleanup on detach
                session.detached.connect((reason, crash) => {
                    logger.info(`Session ${sessionId} detached: ${reason}${crash ? ' (crashed)' : ''}`);
                    cleanupSession(sessionId);
                });
                
                logger.info(`Session ${sessionId} created successfully`);
                
                const result = {
                    status: 'success',
                    process_id,
                    session_id: sessionId,
                    message: `Interactive session created for process ${process_id}. Use execute_in_session to run JavaScript commands.`
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
    
    // Execute in Session
    server.registerTool(
        'execute_in_session',
        {
            title: 'Execute in Session',
            description: 'Execute JavaScript code within an existing Frida session. keep_alive=false (default): Script runs once, results in initial_logs. keep_alive=true: Script persists for hooks, retrieve messages via frida://sessions/{session_id}/messages resource.',
            inputSchema: {
                session_id: z.string().describe('Session ID from create_interactive_session'),
                javascript_code: z.string().describe('JavaScript code to execute'),
                keep_alive: z.boolean().optional().default(false).describe('If true, script persists; if false, runs once')
            },
            outputSchema: {
                status: z.string(),
                result: z.string().optional(),
                initial_logs: z.array(z.string()).optional(),
                error: z.string().optional(),
                stack: z.string().optional(),
                script_unloaded: z.boolean().optional(),
                message: z.string().optional(),
                info: z.string().optional()
            }
        },
        async ({ session_id, javascript_code, keep_alive = false }: { 
            session_id: string; 
            javascript_code: string; 
            keep_alive?: boolean;
        }) => {
            const session = sessions.get(session_id);
            if (!session) {
                const result = {
                    status: 'error',
                    error: `Session with ID ${session_id} not found`
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            }
            
            try {
                // Create script directly without wrapper - preserves line numbers
                const script = await session.createScript(javascript_code);
                
                // Capture messages during execution
                const logs: string[] = [];
                let scriptError: { message: string; stack?: string; fileName?: string; lineNumber?: number; columnNumber?: number } | null = null;
                
                const handleMessage = (message: frida.Message, data: Buffer | null) => {
                    if (message.type === 'send') {
                        // Frida sends console.log output here automatically
                        const payload = message.payload;
                        logs.push(typeof payload === 'string' ? payload : JSON.stringify(payload));
                    } else if (message.type === 'error') {
                        // Error messages include correct line numbers
                        scriptError = {
                            message: message.description || 'Script error',
                            stack: message.stack,
                            fileName: message.fileName,
                            lineNumber: message.lineNumber,
                            columnNumber: message.columnNumber
                        };
                    }
                };
                
                const handlePersistentMessage = (message: frida.Message, data: Buffer | null) => {
                    // Handle binary data serialization
                    const messageData: ScriptMessage = {
                        type: message.type,
                        payload: message.type === 'send' ? message.payload : undefined,
                        data: null
                    };
                    
                    // Handle error messages with full details
                    if (message.type === 'error') {
                        messageData.payload = {
                            description: message.description,
                            stack: message.stack,
                            fileName: message.fileName,
                            lineNumber: message.lineNumber,
                            columnNumber: message.columnNumber
                        };
                    }
                    
                    // If there's binary data, base64 encode it
                    if (data !== null) {
                        try {
                            messageData.data = data.toString('base64');
                        } catch (error) {
                            logger.error(`Failed to encode binary data: ${error}`);
                        }
                    }
                    
                    // Add message to queue
                    const messageQueue = scriptMessages.get(session_id);
                    if (messageQueue) {
                        messageQueue.push(messageData);
                        logger.debug(`Queued message type=${message.type}, queue_size=${messageQueue.length}`);
                    }
                };
                
                if (keep_alive) {
                    script.message.connect(handlePersistentMessage);
                    const sessionScripts = scripts.get(session_id);
                    if (sessionScripts) {
                        sessionScripts.push(script);
                    }
                } else {
                    script.message.connect(handleMessage);
                }
                
                await script.load();
                
                // Give a short time for initial execution
                if (!keep_alive) {
                    await sleep(200);
                }
                
                // Process results
                let finalResult: any = {};
                if (scriptError) {
                    finalResult = {
                        status: 'error',
                        error: scriptError.message,
                        stack: scriptError.stack,
                        fileName: scriptError.fileName,
                        lineNumber: scriptError.lineNumber,
                        columnNumber: scriptError.columnNumber,
                        logs
                    };
                } else if (keep_alive) {
                    finalResult = {
                        status: 'success',
                        message: 'Script loaded persistently. Use frida://sessions/{session_id}/messages to retrieve messages.',
                        logs
                    };
                } else {
                    finalResult = {
                        status: 'success',
                        message: 'Script executed successfully.',
                        logs
                    };
                }
                
                if (!keep_alive) {
                    await script.unload();
                    finalResult.script_unloaded = true;
                } else {
                    finalResult.script_unloaded = false;
                    finalResult.info = 'Script is persistent. Messages will be queued.';
                }
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(finalResult, null, 2) }],
                    structuredContent: finalResult
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
    
    // Load Script File
    server.registerTool(
        'load_script_file',
        {
            title: 'Load Script File',
            description: 'Load and execute a Frida JavaScript file into an existing session.',
            inputSchema: {
                session_id: z.string().describe('Session ID from create_interactive_session'),
                script_path: z.string().describe('Path to JavaScript file'),
                keep_alive: z.boolean().optional().default(true).describe('If true, script persists; if false, runs once')
            },
            outputSchema: {
                status: z.string(),
                script_file: z.string().optional(),
                error: z.string().optional()
            }
        },
        async ({ session_id, script_path, keep_alive = true }: {
            session_id: string;
            script_path: string;
            keep_alive?: boolean;
        }) => {
            const session = sessions.get(session_id);
            if (!session) {
                const result = {
                    status: 'error',
                    error: `Session with ID ${session_id} not found`
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            }
            
            try {
                // Read the script file from filesystem
                const fs = await import('fs/promises');
                const javascriptCode = await fs.readFile(script_path, 'utf-8');
                
                // Create script directly without wrapper - preserves line numbers
                const script = await session.createScript(javascriptCode);
                
                // Capture messages during execution
                const logs: string[] = [];
                let scriptError: { message: string; stack?: string; fileName?: string; lineNumber?: number; columnNumber?: number } | null = null;
                
                const handleMessage = (message: frida.Message, data: Buffer | null) => {
                    if (message.type === 'send') {
                        // Frida sends console.log output here automatically
                        const payload = message.payload;
                        logs.push(typeof payload === 'string' ? payload : JSON.stringify(payload));
                    } else if (message.type === 'error') {
                        // Error messages include correct line numbers
                        scriptError = {
                            message: message.description || 'Script error',
                            stack: message.stack,
                            fileName: message.fileName,
                            lineNumber: message.lineNumber,
                            columnNumber: message.columnNumber
                        };
                    }
                };
                
                const handlePersistentMessage = (message: frida.Message, data: Buffer | null) => {
                    // Handle binary data serialization
                    const messageData: ScriptMessage = {
                        type: message.type,
                        payload: message.type === 'send' ? message.payload : undefined,
                        data: null
                    };
                    
                    // Handle error messages with full details
                    if (message.type === 'error') {
                        messageData.payload = {
                            description: message.description,
                            stack: message.stack,
                            fileName: message.fileName,
                            lineNumber: message.lineNumber,
                            columnNumber: message.columnNumber
                        };
                    }
                    
                    // If there's binary data, base64 encode it
                    if (data !== null) {
                        try {
                            messageData.data = data.toString('base64');
                        } catch (error) {
                            logger.error(`Failed to encode binary data: ${error}`);
                        }
                    }
                    
                    // Add message to queue
                    const messageQueue = scriptMessages.get(session_id);
                    if (messageQueue) {
                        messageQueue.push(messageData);
                        logger.debug(`Queued message type=${message.type}, queue_size=${messageQueue.length}`);
                    }
                };
                
                if (keep_alive) {
                    script.message.connect(handlePersistentMessage);
                    const sessionScripts = scripts.get(session_id);
                    if (sessionScripts) {
                        sessionScripts.push(script);
                    }
                } else {
                    script.message.connect(handleMessage);
                }
                
                await script.load();
                
                // Give a short time for initial execution
                if (!keep_alive) {
                    await sleep(200);
                }
                
                // Process results
                let finalResult: any = {};
                if (scriptError !== null) {
                    finalResult = {
                        status: 'error',
                        error: scriptError.message,
                        stack: scriptError.stack,
                        fileName: scriptError.fileName,
                        lineNumber: scriptError.lineNumber,
                        columnNumber: scriptError.columnNumber,
                        script_file: script_path,
                        logs
                    };
                } else if (keep_alive) {
                    finalResult = {
                        status: 'success',
                        message: 'Script file loaded persistently. Use frida://sessions/{session_id}/messages to retrieve messages.',
                        script_file: script_path,
                        logs
                    };
                } else {
                    finalResult = {
                        status: 'success',
                        message: 'Script file executed successfully.',
                        script_file: script_path,
                        logs
                    };
                }
                
                if (!keep_alive) {
                    await script.unload();
                    finalResult.script_unloaded = true;
                } else {
                    finalResult.script_unloaded = false;
                    finalResult.info = 'Script is persistent. Messages will be queued.';
                }
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(finalResult, null, 2) }],
                    structuredContent: finalResult
                };
                
            } catch (error) {
                const result = {
                    status: 'error',
                    error: error instanceof Error ? error.message : String(error),
                    script_file: script_path
                };
                
                return {
                    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
                    structuredContent: result
                };
            }
        }
    );
    
}