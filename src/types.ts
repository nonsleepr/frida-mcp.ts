/**
 * Type definitions for Frida MCP Server
 */

export interface FridaDevice {
    id: string;
    name: string;
    type: string;
}

export interface FridaProcess {
    pid: number;
    name: string;
}

export interface FridaModule {
    name: string;
    base: string;
    size: number;
    path: string;
}

export interface ScriptMessage {
    type: string;
    payload?: any;
    data?: string | null;  // base64 encoded binary data
}

/**
 * REMOVED: ExecutionReceipt is no longer used.
 * Scripts now execute directly and use Frida's native error reporting.
 */

export interface SessionInfo {
    session_id: string;
    is_alive: boolean;
    is_detached: boolean;
    active_scripts: number;
    pending_messages: number;
    error?: string;
}