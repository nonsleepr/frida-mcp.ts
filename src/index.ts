#!/usr/bin/env bun

/**
 * Frida MCP Server - Main Entry Point
 * 
 * This server provides dynamic instrumentation capabilities through Frida,
 * supporting both local and remote device connections.
 * 
 * Usage:
 *     # stdio mode (default, for Claude Desktop/Roo)
 *     bun run src/index.ts
 *     
 *     # Streamable HTTP mode (recommended for production)
 *     bun run src/index.ts --transport streamable-http --host 0.0.0.0 --port 8000
 *     
 *     # SSE mode (legacy, for backward compatibility)
 *     bun run src/index.ts --transport sse --host 127.0.0.1 --port 8000
 *     
 * Environment variables:
 *     FRIDA_DEFAULT_DEVICE: Default remote device connection string (e.g., "192.168.1.100:27042" or "192.168.1.100")
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { logger } from './logger.js';
import { registerDeviceTools } from './tools/device-tools.js';
import { registerProcessTools } from './tools/process-tools.js';
import { registerSessionTools } from './tools/session-tools.js';
import { registerFileTools } from './tools/file-tools.js';
import { registerResources } from './resources.js';

/**
 * Initialize and configure the MCP server
 */
async function initializeServer(): Promise<McpServer> {
    const server = new McpServer({
        name: 'Frida Dynamic Instrumentation',
        version: '1.0.0'
    });
    
    // Register all tools
    registerDeviceTools(server);
    registerProcessTools(server);
    registerSessionTools(server);
    registerFileTools(server);
    
    // Register all resources
    registerResources(server);
    
    logger.info('Frida MCP Server initialized');
    
    return server;
}

/**
 * Main function to run the Frida MCP server
 */
async function main(): Promise<void> {
    // Parse command line arguments
    const args = process.argv.slice(2);
    const transport = args.includes('--transport')
        ? args[args.indexOf('--transport') + 1] || 'stdio'
        : 'stdio';
    const host = args.includes('--host')
        ? args[args.indexOf('--host') + 1] || '127.0.0.1'
        : '127.0.0.1';
    const port = args.includes('--port')
        ? parseInt(args[args.indexOf('--port') + 1] || '8000', 10)
        : 8000;
    
    // Initialize server
    const server = await initializeServer();
    
    if (transport === 'stdio') {
        logger.info('Starting Frida MCP server in stdio mode');
        const stdioTransport = new StdioServerTransport();
        await server.connect(stdioTransport);
    } else if (transport === 'streamable-http') {
        logger.info(`Starting Frida MCP server in streamable-http mode on ${host}:${port}`);
        logger.error('Streamable HTTP transport not yet implemented in this version');
        logger.error('Please use stdio mode or implement HTTP transport');
        process.exit(1);
    } else if (transport === 'sse') {
        logger.info(`Starting Frida MCP server in SSE mode on ${host}:${port}`);
        logger.error('SSE transport not yet implemented in this version');
        logger.error('Please use stdio mode or implement SSE transport');
        process.exit(1);
    } else {
        logger.error(`Unknown transport: ${transport}`);
        logger.error('Supported transports: stdio, streamable-http, sse');
        process.exit(1);
    }
}

// Run the server if this is the main module
if (import.meta.main) {
    main().catch(error => {
        logger.error('Fatal error:', error);
        process.exit(1);
    });
}

export { main, initializeServer };