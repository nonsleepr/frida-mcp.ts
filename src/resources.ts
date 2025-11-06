/**
 * MCP resource registration for Frida
 */

import * as frida from 'frida';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getDevice, getSessionMessagesAsync, cleanupSession } from './helpers.js';
import { logger } from './logger.js';
import { sessions, scripts, scriptMessages } from './state.js';
import type { SessionInfo } from './types.js';

/**
 * Register MCP resources with the server
 */
export function registerResources(server: McpServer): void {
    
    // Frida version resource
    server.registerResource(
        'frida-version',
        'frida://version',
        {
            name: 'Frida Version',
            description: 'Get Frida version information',
            mimeType: 'text/plain'
        },
        async () => ({
            contents: [{
                uri: 'frida://version',
                text: '17.0.0', // Frida version - static for now
                mimeType: 'text/plain'
            }]
        })
    );
    
    // Devices resource
    server.registerResource(
        'frida-devices',
        'frida://devices',
        {
            name: 'Frida Devices',
            description: 'List all connected Frida devices',
            mimeType: 'text/plain'
        },
        async () => {
            const devices = await frida.enumerateDevices();
            const text = devices.map(d => 
                `ID: ${d.id}, Name: ${d.name}, Type: ${d.type}`
            ).join('\n');
            
            return {
                contents: [{
                    uri: 'frida://devices',
                    text,
                    mimeType: 'text/plain'
                }]
            };
        }
    );
    
    // Processes resource
    server.registerResource(
        'frida-processes',
        'frida://processes',
        {
            name: 'Frida Processes',
            description: 'List all processes from default device',
            mimeType: 'text/plain'
        },
        async () => {
            const device = await getDevice();
            const processes = await device.enumerateProcesses();
            const text = processes.map(p => 
                `PID: ${p.pid}, Name: ${p.name}`
            ).join('\n');
            
            return {
                contents: [{
                    uri: 'frida://processes',
                    text,
                    mimeType: 'text/plain'
                }]
            };
        }
    );
    
    // Sessions resource
    server.registerResource(
        'frida-sessions',
        'frida://sessions',
        {
            name: 'Frida Sessions',
            description: 'List all active Frida sessions and their statuses',
            mimeType: 'application/json'
        },
        async () => {
            const sessionsInfo: SessionInfo[] = [];
            
            for (const [sessionId, session] of sessions) {
                try {
                    const isDetached = session.isDetached();
                    const scriptCount = scripts.get(sessionId)?.length || 0;
                    const messageQueue = scriptMessages.get(sessionId);
                    const messageCount = messageQueue ? messageQueue.length : 0;
                    
                    sessionsInfo.push({
                        session_id: sessionId,
                        is_alive: !isDetached,
                        is_detached: isDetached,
                        active_scripts: scriptCount,
                        pending_messages: messageCount
                    });
                } catch (error) {
                    sessionsInfo.push({
                        session_id: sessionId,
                        is_alive: false,
                        is_detached: true,
                        error: error instanceof Error ? error.message : String(error),
                        active_scripts: 0,
                        pending_messages: 0
                    });
                }
            }
            
            const result = {
                total_sessions: sessionsInfo.length,
                sessions: sessionsInfo
            };
            
            return {
                contents: [{
                    uri: 'frida://sessions',
                    text: JSON.stringify(result, null, 2),
                    mimeType: 'application/json'
                }]
            };
        }
    );
    
    // Session messages resource (dynamic)
    server.registerResource(
        'session-messages',
        'frida://sessions/{sessionId}/messages',
        {
            name: 'Session Messages',
            description: 'Retrieve messages from persistent scripts (messages are consumed)',
            mimeType: 'application/json'
        },
        async (uri: URL) => {
            const pathParts = uri.pathname.split('/');
            const sessionId = pathParts[pathParts.length - 2] || '';
            
            logger.info(`Message retrieval requested for session ${sessionId}`);
            const startTime = Date.now();
            
            try {
                // Validate session exists and is alive
                const session = sessions.get(sessionId);
                if (session) {
                    const isDetached = session.isDetached();
                    logger.debug(`Session found, is_detached=${isDetached}`);
                    if (isDetached) {
                        logger.warning(`Session ${sessionId} is detached, cleaning up`);
                        cleanupSession(sessionId);
                        
                        const result = {
                            status: 'error',
                            error: `Session ${sessionId} is detached and has been cleaned up`,
                            session_id: sessionId
                        };
                        
                        return {
                            contents: [{
                                uri: uri.href,
                                text: JSON.stringify(result, null, 2),
                                mimeType: 'application/json'
                            }]
                        };
                    }
                } else {
                    logger.warning(`Session ${sessionId} not in sessions dict`);
                }
                
                // Use the async function with timeout protection (50s to leave margin)
                logger.debug('Calling getSessionMessagesAsync with 50s timeout');
                const result = await Promise.race([
                    getSessionMessagesAsync(sessionId, 50000),
                    new Promise<any>((_, reject) => 
                        setTimeout(() => reject(new Error('Timeout')), 55000)
                    )
                ]);
                
                const elapsed = (Date.now() - startTime) / 1000;
                logger.info(`Success in ${elapsed.toFixed(3)}s, returning ${result.messages_retrieved || 0} messages`);
                
                return {
                    contents: [{
                        uri: uri.href,
                        text: JSON.stringify(result, null, 2),
                        mimeType: 'application/json'
                    }]
                };
                
            } catch (error) {
                const elapsed = (Date.now() - startTime) / 1000;
                logger.error(`Exception after ${elapsed.toFixed(3)}s: ${error}`);
                
                const result = {
                    status: 'error',
                    error: `Failed to retrieve messages: ${error instanceof Error ? error.message : String(error)}`,
                    session_id: sessionId,
                    elapsed_seconds: Math.round(elapsed * 1000) / 1000
                };
                
                return {
                    contents: [{
                        uri: uri.href,
                        text: JSON.stringify(result, null, 2),
                        mimeType: 'application/json'
                    }]
                };
            }
        }
    );
}