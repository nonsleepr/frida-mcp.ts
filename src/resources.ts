
/**
 * MCP resource registration for Frida
 */

import * as frida from 'frida';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { getDevice, getSessionMessages, cleanupSession } from './helpers.js';
import { logger } from './logger.js';
import { sessions, scripts, scriptMessages } from './state.js';
import type { SessionInfo } from './types.js';

/**
 * Register MCP resources with the server
 */
export function registerResources(server: McpServer): void {
    
    // Devices resource (static list)
    server.registerResource(
        'frida-devices',
        'frida://devices',
        {
            name: 'Frida Devices',
            description: 'List all connected Frida devices',
            mimeType: 'application/json'
        },
        async () => {
            const devices = await frida.enumerateDevices();
            const deviceList = devices.map(d => ({
                id: d.id,
                name: d.name,
                type: d.type
            }));
            
            return {
                contents: [{
                    uri: 'frida://devices',
                    text: JSON.stringify(deviceList, null, 2),
                    mimeType: 'application/json'
                }]
            };
        }
    );
    
    // Device processes resource template
    server.registerResource(
        'device-processes',
        new ResourceTemplate('frida://devices/{device_id}/processes', { list: undefined }),
        {
            name: 'Device Processes',
            description: 'List processes on a specific Frida device. Use "local", "usb", or "remote" for automatic device selection, provide a specific device ID, or use a connection string (hostname:port or hostname).',
            mimeType: 'application/json'
        },
        async (uri, { device_id }) => {
            const deviceIdParam = String(device_id || '');
            
            // Map special keywords to device selection
            let deviceId: string | undefined;
            if (deviceIdParam === 'local' || deviceIdParam === 'usb' || deviceIdParam === 'remote') {
                deviceId = undefined; // Let getDevice handle auto-selection
            } else {
                // Pass through - getDevice will handle connection strings
                deviceId = deviceIdParam;
            }
            
            try {
                const device = await getDevice(deviceId);
                const processes = await device.enumerateProcesses();
                const processList = processes.map(p => ({
                    pid: p.pid,
                    name: p.name
                }));
                
                return {
                    contents: [{
                        uri: uri.href,
                        text: JSON.stringify(processList, null, 2),
                        mimeType: 'application/json'
                    }]
                };
            } catch (error) {
                const errorResult = {
                    error: `Failed to enumerate processes: ${error instanceof Error ? error.message : String(error)}`,
                    device_id: deviceIdParam
                };
                
                return {
                    contents: [{
                        uri: uri.href,
                        text: JSON.stringify(errorResult, null, 2),
                        mimeType: 'application/json'
                    }]
                };
            }
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
    
    // Device info resource template
    server.registerResource(
        'device-info',
        new ResourceTemplate('frida://devices/{device_id}', { list: undefined }),
        {
            name: 'Device Info',
            description: 'Get detailed information about a specific device by ID',
            mimeType: 'application/json'
        },
        async (uri, { device_id }) => {
            const deviceId = String(device_id || '');
            
            try {
                const device = await frida.getDevice(deviceId);
                const result = {
                    id: device.id,
                    name: device.name,
                    type: device.type
                };
                
                return {
                    contents: [{
                        uri: uri.href,
                        text: JSON.stringify(result, null, 2),
                        mimeType: 'application/json'
                    }]
                };
            } catch (error) {
                const errorResult = {
                    error: `Device with ID ${deviceId} not found`,
                    device_id: deviceId
                };
                
                return {
                    contents: [{
                        uri: uri.href,
                        text: JSON.stringify(errorResult, null, 2),
                        mimeType: 'application/json'
                    }]
                };
            }
        }
    );
    
    // Process by name resource template
    server.registerResource(
        'process-by-name',
        new ResourceTemplate('frida://devices/{device_id}/processes/by-name/{process_name}', { list: undefined }),
        {
            name: 'Process by Name',
            description: 'Find a process by name (case-insensitive partial match) on a specific device. Supports connection strings (hostname:port or hostname).',
            mimeType: 'application/json'
        },
        async (uri, { device_id, process_name }) => {
            const deviceIdParam = String(device_id || '');
            const processName = decodeURIComponent(String(process_name || ''));
            
            // Map special keywords to device selection
            let deviceId: string | undefined;
            if (deviceIdParam === 'local' || deviceIdParam === 'usb' || deviceIdParam === 'remote') {
                deviceId = undefined;
            } else {
                // Pass through - getDevice will handle connection strings
                deviceId = deviceIdParam;
            }
            
            try
 {
                const device = await getDevice(deviceId);
                const processes = await device.enumerateProcesses();
                
                for (const proc of processes) {
                    if (proc.name.toLowerCase().includes(processName.toLowerCase())) {
                        const result = {
                            pid: proc.pid,
                            name: proc.name,
                            found: true
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
                
                const result = {
                    found: false,
                    error: `Process '${processName}' not found`,
                    device_id: deviceIdParam
                };
                
                return {
                    contents: [{
                        uri: uri.href,
                        text: JSON.stringify(result, null, 2),
                        mimeType: 'application/json'
                    }]
                };
            } catch (error) {
                const errorResult = {
                    found: false,
                    error: `Failed to search for process: ${error instanceof Error ? error.message : String(error)}`,
                    device_id: deviceIdParam,
                    process_name: processName
                };
                
                return {
                    contents: [{
                        uri: uri.href,
                        text: JSON.stringify(errorResult, null, 2),
                        mimeType: 'application/json'
                    }]
                };
            }
        }
    );
    
    // Process module path resource template
    server.registerResource(
        'process-module-path',
        new ResourceTemplate('frida://devices/{device_id}/processes/{pid}/module', { list: undefined }),
        {
            name: 'Process Module Path',
            description: 'Get main module information for a process (path, base address, size). Supports connection strings (hostname:port or hostname).',
            mimeType: 'application/json'
        },
        async (uri, { device_id, pid }) => {
            const deviceIdParam = String(device_id || '');
            const pidStr = String(pid || '');
            const pidNum = parseInt(pidStr, 10);
            
            if (isNaN(pidNum)) {
                const errorResult = {
                    status: 'error',
                    error: `Invalid PID: ${pidStr}`
                };
                
                return {
                    contents: [{
                        uri: uri.href,
                        text: JSON.stringify(errorResult, null, 2),
                        mimeType: 'application/json'
                    }]
                };
            }
            
            // Map special keywords to device selection
            let deviceId: string | undefined;
            if (deviceIdParam === 'local' || deviceIdParam === 'usb' || deviceIdParam === 'remote') {
                deviceId = undefined;
            } else {
                // Pass through - getDevice will handle connection strings
                deviceId = deviceIdParam;
            }
            
            try {
                const device = await getDevice(deviceId);
                const session = await device.attach(pidNum);
                
                const script = await session.createScript(`
                    var mainModule = Process.enumerateModules()[0];
                    send({
                        name: mainModule.name,
                        path: mainModule.path,
                        base: mainModule.base.toString(),
                        size: mainModule.size
                    });
                `);
                
                const results: any[] = [];
                script.message.connect((message: frida.Message) => {
                    if (message.type === 'send') {
                        results.push(message.payload);
                    }
                });
                
                await script.load();
                
                // Wait for result
                await new Promise(resolve => setTimeout(resolve, 100));
                
                await script.unload();
                await session.detach();
                
                if (results.length > 0) {
                    const result = {
                        status: 'success',
                        pid: pidNum,
                        ...results[0]
                    };
                    
                    return {
                        contents: [{
                            uri: uri.href,
                            text: JSON.stringify(result, null, 2),
                            mimeType: 'application/json'
                        }]
                    };
                } else {
                    const result = {
                        status: 'error',
                        error: 'Failed to get module information',
                        pid: pidNum
                    };
                    
                    return {
                        contents: [{
                            uri: uri.href,
                            text: JSON.stringify(result, null, 2),
                            mimeType: 'application/json'
                        }]
                    };
                }
            } catch (error) {
                const result = {
                    status: 'error',
                    error: error instanceof Error ? error.message : String(error),
                    pid: pidNum
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
    
    // Session messages resource template (base - default 100 limit)
    server.registerResource(
        'session-messages',
        new ResourceTemplate('frida://sessions/{sessionId}/messages', { list: undefined }),
        {
            name: 'Session Messages',
            description: 'Retrieve messages from persistent scripts with default 100 message limit. Messages are consumed when retrieved.',
            mimeType: 'application/json'
        },
        async (uri, { sessionId }) => {
            const sessionIdStr = String(sessionId || '');
            const limit: number | undefined = 100; // Default limit
            
            logger.info(`Message retrieval requested for session ${sessionIdStr}, limit=${limit || 'unlimited'}`);
            const startTime = Date.now();
            
            try {
                // Validate session exists and is alive
                const session = sessions.get(sessionIdStr);
                if (session) {
                    const isDetached = session.isDetached();
                    logger.debug(`Session found, is_detached=${isDetached}`);
                    if (isDetached) {
                        logger.warning(`Session ${sessionIdStr} is detached, cleaning up`);
                        cleanupSession(sessionIdStr);
                        
                        const result = {
                            status: 'error',
                            error: `Session ${sessionIdStr} is detached and has been cleaned up`,
                            session_id: sessionIdStr
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
                    logger.warning(`Session ${sessionIdStr} not in sessions dict`);
                }
                
                // Get messages immediately (event-driven, no polling)
                logger.debug('Retrieving session messages');
                const result = getSessionMessages(sessionIdStr);
                
                // Apply limit if specified
                if (result.status === 'success' && result.messages && limit !== undefined) {
                    const originalCount = result.messages.length;
                    result.messages = result.messages.slice(-limit);
                    result.messages_retrieved = result.messages.length;
                    if (result.messages.length < originalCount) {
                        result.info = `Retrieved last ${result.messages.length} of ${originalCount} available messages`;
                    }
                }
                
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
                    session_id: sessionIdStr,
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
    
    // Session messages resource template with limit parameter
    server.registerResource(
        'session-messages-with-limit',
        new ResourceTemplate('frida://sessions/{sessionId}/messages/{limit}', { list: undefined }),
        {
            name: 'Session Messages',
            description: 'Retrieve messages from persistent scripts. Use /last:N to limit results (e.g., /last:10 for last 10 messages) or /all for unlimited. Messages are consumed when retrieved.',
            mimeType: 'application/json'
        },
        async (uri, { sessionId, limit: limitParam }) => {
            const sessionIdStr = String(sessionId || '');
            let limit: number | undefined = 100; // Default limit
            
            // Parse limit parameter
            if (limitParam) {
                const limitStr = String(limitParam);
                if (limitStr.startsWith('last:')) {
                    const limitValue = parseInt(limitStr.substring(5), 10);
                    if (!isNaN(limitValue) && limitValue > 0) {
                        limit = limitValue;
                    }
                } else if (limitStr === 'all') {
                    limit = undefined; // No limit
                }
            }
            
            logger.info(`Message retrieval requested for session ${sessionIdStr}, limit=${limit || 'unlimited'}`);
            const startTime = Date.now();
            
            try {
                // Validate session exists and is alive
                const session = sessions.get(sessionIdStr);
                if (session) {
                    const isDetached = session.isDetached();
                    logger.debug(`Session found, is_detached=${isDetached}`);
                    if (isDetached) {
                        logger.warning(`Session ${sessionIdStr} is detached, cleaning up`);
                        cleanupSession(sessionIdStr);
                        
                        const result = {
                            status: 'error',
                            error: `Session ${sessionIdStr} is detached and has been cleaned up`,
                            session_id: sessionIdStr
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
                    logger.warning(`Session ${sessionIdStr} not in sessions dict`);
                }
                
                // Get messages immediately (event-driven, no polling)
                logger.debug('Retrieving session messages');
                const result = getSessionMessages(sessionIdStr);
                
                // Apply limit if specified
                if (result.status === 'success' && result.messages && limit !== undefined) {
                    const originalCount = result.messages.length;
                    result.messages = result.messages.slice(-limit);
                    result.messages_retrieved = result.messages.length;
                    if (result.messages.length < originalCount) {
                        result.info = `Retrieved last ${result.messages.length} of ${originalCount} available messages`;
                    }
                }
                
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
                    session_id: sessionIdStr,
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