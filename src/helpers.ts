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
 * 1. If device_id is specified, use that exact device
 * 2. If FRIDA_REMOTE_HOST env var is set, use remote device
 * 3. Try USB device (for mobile device debugging)
 * 4. Fall back to local device (for local process instrumentation)
 * 
 * @param deviceId - Optional specific device ID to use
 * @returns The selected Frida device
 * 
 * Environment Variables:
 *     FRIDA_REMOTE_HOST: Remote Frida server hostname/IP
 *     FRIDA_REMOTE_PORT: Remote Frida server port (default: 27042)
 */
export async function getDevice(deviceId?: string): Promise<frida.Device> {
    // Priority 1: Explicit device ID provided
    if (deviceId) {
        return await frida.getDevice(deviceId);
    }
    
    // Priority 2: Remote device via environment variables
    const remoteHost = process.env.FRIDA_REMOTE_HOST;
    if (remoteHost) {
        const remotePort = parseInt(process.env.FRIDA_REMOTE_PORT || '27042', 10);
        const deviceManager = frida.getDeviceManager();
        const remoteAddress = `${remoteHost}:${remotePort}`;
        logger.info(`Using remote device: ${remoteAddress}`);
        return await deviceManager.addRemoteDevice(remoteAddress);
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
export function cleanupSession(sessionId: string): void {
    // Detach session if exists
    const session = sessions.get(sessionId);
    if (session) {
        try {
            session.detach();
        } catch (error) {
            // Ignore errors during cleanup
        }
        sessions.delete(sessionId);
    }
    
    // Unload and clean up scripts
    const sessionScripts = scripts.get(sessionId);
    if (sessionScripts) {
        for (const script of sessionScripts) {
            try {
                script.unload();
            } catch (error) {
                // Ignore errors during cleanup
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
 * 
 * @param sessionId - Session ID to retrieve messages from
 * @param timeout - Maximum milliseconds to wait for messages (default: 5000ms)
 * @returns Object with status and messages list
 */
export async function getSessionMessagesAsync(
    sessionId: string,
    timeout: number = 5000
): Promise<{
    status: string;
    session_id?: string;
    messages?: ScriptMessage[];
    messages_retrieved?: number;
    elapsed_seconds?: number;
    error?: string;
    info?: string;
}> {
    logger.info(`Retrieving messages for session ${sessionId}`);
    const startTime = Date.now();
    
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
        
        const messages: ScriptMessage[] = [];
        const deadline = Date.now() + timeout;
        
        // Collect all available messages with timeout
        while (Date.now() < deadline) {
            const remaining = deadline - Date.now();
            if (remaining <= 0) {
                break;
            }
            
            // Since we're using an array-based queue, just drain it
            if (messageQueue.length > 0) {
                messages.push(...messageQueue.splice(0, messageQueue.length));
                break;
            }
            
            // Small delay before checking again
            await sleep(Math.min(100, remaining));
        }
        
        const elapsed = (Date.now() - startTime) / 1000;
        logger.info(`Retrieved ${messages.length} messages in ${elapsed.toFixed(3)}s`);
        
        return {
            status: 'success',
            session_id: sessionId,
            messages,
            messages_retrieved: messages.length,
            elapsed_seconds: Math.round(elapsed * 1000) / 1000
        };
        
    } catch (error) {
        const elapsed = (Date.now() - startTime) / 1000;
        logger.error(`Exception retrieving messages: ${error}`);
        return {
            status: 'error',
            error: `Failed to retrieve messages: ${error instanceof Error ? error.message : String(error)}`,
            session_id: sessionId,
            elapsed_seconds: Math.round(elapsed * 1000) / 1000
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