
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
import { CONSOLE_INTERCEPTOR } from '../scripts.js';

/**
 * Process captured logs to normalize console messages and detect errors
 */
function processLogs(logs: any[]): { processedLogs: any[], firstError: any | null } {
    const processedLogs: any[] = [];
    let firstError: any | null = null;
    
    for (const log of logs) {
        // Handle console.* messages - flatten the structure
        if (log.type === 'send' && log.payload && typeof log.payload === 'object' &&
            typeof log.payload.type === 'string' && log.payload.type.startsWith('console.')) {
            // Extract console type and message
            const consoleType = log.payload.type;
            const message = log.payload.message;
            
            processedLogs.push({
                type: consoleType,
                message: message,
                data: log.data
            });
        }
        // Handle error messages
        else if (log.type === 'error') {
            // Capture first error for top-level error reporting
            if (!firstError && log.payload) {
                firstError = {
                    description: log.payload.description,
                    stack: log.payload.stack,
                    fileName: log.payload.fileName,
                    lineNumber: log.payload.lineNumber,
                    columnNumber: log.payload.columnNumber
                };
            }
            // Keep error in logs as-is
            processedLogs.push(log);
        }
        // Handle regular send messages and other types
        else {
            processedLogs.push(log);
        }
    }
    
    return { processedLogs, firstError };
}

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
            description: 'Execute JavaScript code within an existing Frida session. All scripts are persistent and continue running. Use wait parameter to capture initial output before returning. Messages available via frida://sessions/{session_id}/messages resource.',
            inputSchema: {
                session_id: z.string().describe('Session ID from create_interactive_session'),
                javascript_code: z.string().describe('JavaScript code to execute'),
                wait: z.number().optional().default(0).describe('Seconds to wait for initial output (0 = return immediately)')
            },
            outputSchema: {
                status: z.string(),
                result: z.string().optional(),
                initial_logs: z.array(z.string()).optional(),
                error: z.string().optional(),
                stack: z.string().optional(),
                message: z.string().optional(),
                info: z.string().optional()
            }
        },
        async ({ session_id, javascript_code, wait = 0 }: {
            session_id: string;
            javascript_code: string;
            wait?: number;
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
                // Prepend console interceptor to capture console.* output
                // The interceptor adds 1 line, so line numbers are offset by 1
                const LINE_OFFSET = 1;
                
                // Generate script name based on number of scripts in session
                const existingScripts = scripts.get(session_id) || [];
                const scriptNumber = existingScripts.length + 1;
                const scriptName = `script${scriptNumber}`;
                
                const wrappedCode = `${CONSOLE_INTERCEPTOR}\n${javascript_code}\n//# sourceURL=/${scriptName}.js`;
                const script = await session.createScript(wrappedCode);
                
                // Capture initial logs - always capture, not just when wait > 0
                const logs: any[] = [];
                let initialCollectionDone = false;
                
                const handlePersistentMessage = (message: frida.Message, data: Buffer | null) => {
                    // Handle binary data serialization
                    const messageData: ScriptMessage = {
                        type: message.type,
                        payload: message.type === 'send' ? message.payload : undefined,
                        data: null
                    };
                    
                    // Handle error messages with full details and adjust line numbers
                    if (message.type === 'error') {
                        const adjustedLineNumber = message.lineNumber ? message.lineNumber - LINE_OFFSET : undefined;
                        messageData.payload = {
                            description: message.description,
                            stack: message.stack,
                            fileName: message.fileName,
                            lineNumber: adjustedLineNumber,
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
                    
                    // Capture ALL message types in initial logs before collection is done
                    if (!initialCollectionDone) {
                        logs.push({
                            type: messageData.type,
                            payload: messageData.payload,
                            data: messageData.data
                        });
                    }
                    
                    // Add message to queue for retrieval
                    const messageQueue = scriptMessages.get(session_id);
                    if (messageQueue) {
                        messageQueue.push(messageData);
                        logger.debug(`Queued message type=${message.type}, queue_size=${messageQueue.length}`);
                    }
                };
                
                // Always use persistent message handler
                script.message.connect(handlePersistentMessage);
                
                // Store script in session
                const sessionScripts = scripts.get(session_id);
                if (sessionScripts) {
                    sessionScripts.push(script);
                }
                
                await script.load();
                
                // Wait for initial output if requested, or small delay to capture immediate messages
                if (wait > 0) {
                    await sleep(wait * 1000);
                } else {
                    // Give a small window to capture synchronous messages
                    await sleep(100);
                }
                
                // Mark initial collection as done
                initialCollectionDone = true;
                
                // Process logs to normalize console messages and detect errors
                const { processedLogs, firstError } = processLogs(logs);
                
                // Build response
                const finalResult: any = {
                    status: firstError ? 'error' : 'success',
                    script_name: scriptName,
                    message: wait > 0
                        ? `Script loaded. Waited ${wait}s for initial output. Script continues running - use frida://sessions/${session_id}/messages to retrieve messages.`
                        : `Script loaded and running persistently. Use frida://sessions/${session_id}/messages to retrieve messages.`,
                    logs: processedLogs,
                    info: 'Script is persistent and will continue running until session ends.'
                };
                
                // Add error details at top level if error occurred
                if (firstError) {
                    finalResult.error = firstError.description;
                    finalResult.stack = firstError.stack;
                    finalResult.fileName = firstError.fileName;
                    finalResult.lineNumber = firstError.lineNumber;
                    finalResult.columnNumber = firstError.columnNumber;
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
            description: 'Load and execute a Frida JavaScript file into an existing session. All scripts are persistent and continue running. Use wait parameter to capture initial output before returning. Messages available via frida://sessions/{session_id}/messages resource.',
            inputSchema: {
                session_id: z.string().describe('Session ID from create_interactive_session'),
                script_path: z.string().describe('Path to JavaScript file'),
                wait: z.number().optional().default(0).describe('Seconds to wait for initial output (0 = return immediately)')
            },
            outputSchema: {
                status: z.string(),
                script_file: z.string().optional(),
                error: z.string().optional()
            }
        },
        async ({ session_id, script_path, wait = 0 }: {
            session_id: string;
            script_path: string;
            wait?: number;
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
                
                // Prepend console interceptor to capture console.* output
                // The interceptor adds 1 line, so line numbers are offset by 1
                const LINE_OFFSET = 1;
                
                // Use the script file path as the script name
                const scriptName = script_path;
                
                const wrappedCode = `${CONSOLE_INTERCEPTOR}\n${javascriptCode}\n//# sourceURL=${scriptName}`;
                const script = await session.createScript(wrappedCode);
                
                // Capture initial logs - always capture, not just when wait > 0
                const logs: any[] = [];
                let initialCollectionDone = false;
                
                const handlePersistentMessage = (message: frida.Message, data: Buffer | null) => {
                    // Handle binary data serialization
                    const messageData: ScriptMessage = {
                        type: message.type,
                        payload: message.type === 'send' ? message.payload : undefined,
                        data: null
                    };
                    
                    // Handle error messages with full details and adjust line numbers
                    if (message.type === 'error') {
                        const adjustedLineNumber = message.lineNumber ? message.lineNumber - LINE_OFFSET : undefined;
                        messageData.payload = {
                            description: message.description,
                            stack: message.stack,
                            fileName: message.fileName,
                            lineNumber: adjustedLineNumber,
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
                    
                    // Capture ALL message types in initial logs before collection is done
                    if (!initialCollectionDone) {
                        logs.push({
                            type: messageData.type,
                            payload: messageData.payload,
                            data: messageData.data
                        });
                    }
                    
                    // Add message to queue for retrieval
                    const messageQueue = scriptMessages.get(session_id);
                    if (messageQueue) {
                        messageQueue.push(messageData);
                        logger.debug(`Queued message type=${message.type}, queue_size=${messageQueue.length}`);
                    }
                };
                
                // Always use persistent message handler
                script.message.connect(handlePersistentMessage);
                
                // Store script in session
                const sessionScripts = scripts.get(session_id);
                if (sessionScripts) {
                    sessionScripts.push(script);
                }
                
                await script.load();
                
                // Wait for initial output if requested, or small delay to capture immediate messages
                if (wait > 0) {
                    await sleep(wait * 1000);
                } else {
                    // Give a small window to capture synchronous messages
                    await sleep(100);
                }
                
                // Mark initial collection as done
                initialCollectionDone = true;
                
                // Process logs to normalize console messages and detect errors
                const { processedLogs, firstError } = processLogs(logs);
                
                // Build response
                const finalResult: any = {
                    status: firstError ? 'error' : 'success',
                    script_name: scriptName,
                    message: wait > 0
                        ? `Script file loaded. Waited ${wait}s for initial output. Script continues running - use frida://sessions/${session_id}/messages to retrieve messages.`
                        : `Script file loaded and running persistently. Use frida://sessions/${session_id}/messages to retrieve messages.`,
                    script_file: script_path,
                    logs: processedLogs,
                    info: 'Script is persistent and will continue running until session ends.'
                };
                
                // Add error details at top level if error occurred
                if (firstError) {
                    finalResult.error = firstError.description;
                    finalResult.stack = firstError.stack;
                    finalResult.fileName = firstError.fileName;
                    finalResult.lineNumber = firstError.lineNumber;
                    finalResult.columnNumber = firstError.columnNumber;
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