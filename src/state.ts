/**
 * Global state management for Frida sessions and scripts
 */

import type * as frida from 'frida';
import type { ScriptMessage } from './types.js';

// Session management - stores active Frida sessions
export const sessions: Map<string, frida.Session> = new Map();

// Script management - stores loaded scripts per session
export const scripts: Map<string, frida.Script[]> = new Map();

// Message queues - stores script messages per session
export const scriptMessages = new Map<string, ScriptMessage[]>();