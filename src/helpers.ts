/**
 * Helper functions for Frida operations
 */

import * as frida from 'frida';
import { logger } from './logger.js';
import { sessions, scripts, scriptMessages } from './state.js';
import type { ScriptMessage } from './types.js';

/**
 * Get a Frida device by ID or use default detection.
 *
 * Device selection priority:
 * 1. If device_id is specified:
 *    - "default" keyword uses FRIDA_DEFAULT_DEVICE or falls back to auto-detection
 *    - Connection strings (hostname:port or hostname) are added as remote devices
 *    - Standard device IDs ("local", "usb", "remote") are resolved via getDevice()
 * 2. If FRIDA_DEFAULT_DEVICE env var is set, use remote device
 * 3. Try USB device (for mobile device debugging)
 * 4. Fall back to local device (for local process instrumentation)
 *
 * @param deviceId - Optional device ID or connection string (hostname:port or hostname)
 * @returns The selected Frida device
 *
 * Environment Variables:
 *     FRIDA_DEFAULT_DEVICE: Default remote device connection string (hostname:port or hostname, port defaults to 27042)
 */
export async function getDevice(deviceId?: string): Promise<frida.Device> {
    // Priority 1: Explicit device ID provided
    if (deviceId) {
        // Handle "default" keyword - use FRIDA_DEFAULT_DEVICE or fall back to auto-detection
        if (deviceId.toLowerCase() === 'default') {
            const defaultDevice = process.env.FRIDA_DEFAULT_DEVICE;
            if (defaultDevice) {
                // Parse connection string (hostname:port or hostname)
                try {
                    const url = new URL(`tcp://${defaultDevice}`);
                    const host = url.hostname;
                    const port = url.port ? parseInt(url.port, 10) : 27042;
                    
                    if (host) {
                        const remoteAddress = `${host}:${port}`;
                        logger.info(`Using default device: ${remoteAddress}`);
                        const deviceManager = frida.getDeviceManager();
                        return await deviceManager.addRemoteDevice(remoteAddress);
                    }
                } catch {
                    // Invalid format, fall through
                }
            }
            
            // If no env vars, fall through to auto-detection (Priority 3 & 4)
            deviceId = undefined;
        }
        
        // Check if it's a connection string by attempting to parse as URL
        // Skip standard device keywords
        if (deviceId && !['local', 'usb', 'remote'].includes(deviceId.toLowerCase())) {
            try {
                // Try parsing as URL with dummy protocol
                const url = new URL(`tcp://${deviceId}`);
                const host = url.hostname;
                const port = url.port ? parseInt(url.port, 10) : 27042;
                
                // If we successfully parsed hostname, treat as connection string
                if (host) {
                    const remoteAddress = `${host}:${port}`;
                    logger.info(`Adding remote device: ${remoteAddress}`);
                    const deviceManager = frida.getDeviceManager();
                    return await deviceManager.addRemoteDevice(remoteAddress);
                }
            } catch {
                // Not a valid URL format, fall through to standard device lookup
            }
        }
        
        // Standard device ID (if still set)
        if (deviceId) {
            return await frida.getDevice(deviceId);
        }
    }
    
    // Priority 2: Remote device via environment variables
    const defaultDevice = process.env.FRIDA_DEFAULT_DEVICE;
    if (defaultDevice) {
        // Parse connection string (hostname:port or hostname)
        try {
            const url = new URL(`tcp://${defaultDevice}`);
            const host = url.hostname;
            const port = url.port ? parseInt(url.port, 10) : 27042;
            
            if (host) {
                const remoteAddress = `${host}:${port}`;
                logger.info(`Using default device from env: ${remoteAddress}`);
                const deviceManager = frida.getDeviceManager();
                return await deviceManager.addRemoteDevice(remoteAddress);
            }
        } catch {
            // Invalid format, fall through
        }
    }
    
    // Priority 3: USB device (for mobile debugging)
    try {
        return await frida.getUsbDevice();
    } catch (error) {
        // Priority 4: Local device (fallback)
        return await frida.getLocalDevice();
    }
}

/**
 * Execute a Frida script and wait for results.
 * 
 * @param session - Active Frida session
 * @param scriptCode - JavaScript code to execute
 * @param timeout - Milliseconds to wait for results (default: 200ms)
 * @returns Array of payloads received from send() calls
 */
export async function executeScriptAndWait(
    session: frida.Session,
    scriptCode: string,
    timeout: number = 200
): Promise<any[]> {
    const script = await session.createScript(scriptCode);
    const results: any[] = [];
    
    script.message.connect((message: frida.Message) => {
        if (message.type === 'send') {
            results.push(message.payload);
        }
    });
    
    await script.load();
    
    // Wait for the specified timeout
    await sleep(timeout);
    
    await script.unload();
    
    return results;
}

/**
 * Clean up a detached or invalid session.
 *
 * @param sessionId - Session ID to clean up
 */
export async function cleanupSession(sessionId: string): Promise<void> {
    // Detach session if exists
    const session = sessions.get(sessionId);
    if (session) {
        try {
            await session.detach();
        } catch (error) {
            // Ignore errors during cleanup - session may already be detached
            logger.debug(`Session detach error (expected if already detached): ${error}`);
        }
        sessions.delete(sessionId);
    }
    
    // Unload and clean up scripts
    const sessionScripts = scripts.get(sessionId);
    if (sessionScripts) {
        for (const script of sessionScripts) {
            try {
                await script.unload();
            } catch (error) {
                // Ignore errors during cleanup - script may already be destroyed
                logger.debug(`Script unload error (expected if already destroyed): ${error}`);
            }
        }
        scripts.delete(sessionId);
    }
    
    // Clear message queue
    if (scriptMessages.has(sessionId)) {
        scriptMessages.delete(sessionId);
    }
}

/**
 * Retrieve and clear messages from persistent scripts.
 * Event-driven approach - returns immediately with available messages.
 * No polling needed since messages are captured in real-time by handlers.
 *
 * @param sessionId - Session ID to retrieve messages from
 * @returns Object with status and messages list
 */
export function getSessionMessages(
    sessionId: string
): {
    status: string;
    session_id?: string;
    messages?: ScriptMessage[];
    messages_retrieved?: number;
    error?: string;
    info?: string;
} {
    logger.info(`Retrieving messages for session ${sessionId}`);
    
    try {
        // Validation checks
        const session = sessions.get(sessionId);
        if (!session) {
            logger.warning(`Session ${sessionId} not in sessions`);
            const sessionScripts = scripts.get(sessionId);
            if (sessionScripts && sessionScripts.length === 0) {
                return {
                    status: 'success',
                    session_id: sessionId,
                    messages: [],
                    messages_retrieved: 0,
                    info: 'Session scripts finished or detached.'
                };
            }
            return {
                status: 'error',
                error: `Session ${sessionId} not found.`
            };
        }
        
        const messageQueue = scriptMessages.get(sessionId);
        if (!messageQueue) {
            return {
                status: 'error',
                error: `Message queue not found for session ${sessionId}.`
            };
        }
        
        // Drain the queue immediately - messages are captured in real-time
        const messages = messageQueue.splice(0, messageQueue.length);
        
        logger.info(`Retrieved ${messages.length} messages`);
        
        return {
            status: 'success',
            session_id: sessionId,
            messages,
            messages_retrieved: messages.length
        };
        
    } catch (error) {
        logger.error(`Exception retrieving messages: ${error}`);
        return {
            status: 'error',
            error: `Failed to retrieve messages: ${error instanceof Error ? error.message : String(error)}`,
            session_id: sessionId
        };
    }
}

/**
 * Sleep for specified milliseconds (utility function)
 */
export function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Execute a promise with timeout protection.
 *
 * @param promise - Promise to execute
 * @param timeoutMs - Maximum milliseconds to wait
 * @param errorContext - Context string for timeout error message
 * @returns Promise that resolves with the result or rejects on timeout
 */
export async function withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    errorContext: string = 'Operation'
): Promise<T> {
    return Promise.race([
        promise,
        new Promise<T>((_, reject) =>
            setTimeout(
                () => reject(new Error(`${errorContext} timed out after ${timeoutMs}ms`)),
                timeoutMs
            )
        )
    ]);
}

/**
 * Generate a unique session ID
 */
export function generateSessionId(processId: number): string {
    return `session_${processId}_${Math.floor(Date.now() / 1000)}`;
}