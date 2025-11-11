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
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { randomUUID } from 'node:crypto';
import express from 'express';
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
 * Start the server in Streamable HTTP mode with session management
 */
async function startStreamableHttpServer(server: McpServer, host: string, port: number): Promise<void> {
    const app = express();
    app.use(express.json());
    
    // Store transports by session ID
    const transports: Record<string, StreamableHTTPServerTransport> = {};
    
    // Handle POST requests for client-to-server communication
    app.post('/mcp', async (req, res) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        let transport: StreamableHTTPServerTransport;
        
        if (sessionId && transports[sessionId]) {
            // Reuse existing transport for this session
            transport = transports[sessionId];
        } else if (!sessionId && isInitializeRequest(req.body)) {
            // New initialization request - create new transport
            transport = new StreamableHTTPServerTransport({
                sessionIdGenerator: () => randomUUID(),
                onsessioninitialized: (id) => {
                    transports[id] = transport;
                    logger.info(`Session initialized: ${id}`);
                },
                enableJsonResponse: true
            });
            
            // Clean up transport when closed
            transport.onclose = () => {
                if (transport.sessionId) {
                    logger.info(`Session closed: ${transport.sessionId}`);
                    delete transports[transport.sessionId];
                }
            };
            
            // Connect to the MCP server
            await server.connect(transport);
        } else {
            // Invalid request
            res.status(400).json({
                jsonrpc: '2.0',
                error: {
                    code: -32000,
                    message: 'Bad Request: No valid session ID provided'
                },
                id: null
            });
            return;
        }
        
        // Handle the request
        await transport.handleRequest(req, res, req.body);
    });
    
    // Handle GET requests for server-to-client notifications via SSE
    app.get('/mcp', async (req, res) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        if (!sessionId || !transports[sessionId]) {
            res.status(400).send('Invalid or missing session ID');
            return;
        }
        
        const transport = transports[sessionId];
        await transport.handleRequest(req, res);
    });
    
    // Handle DELETE requests for session termination
    app.delete('/mcp', async (req, res) => {
        const sessionId = req.headers['mcp-session-id'] as string | undefined;
        if (!sessionId || !transports[sessionId]) {
            res.status(400).send('Invalid or missing session ID');
            return;
        }
        
        const transport = transports[sessionId];
        await transport.handleRequest(req, res);
    });
    
    // Start the server
    app.listen(port, host, () => {
        logger.info(`Frida MCP server listening on http://${host}:${port}/mcp`);
    }).on('error', (error) => {
        logger.error('Server error:', error);
        process.exit(1);
    });
}

/**
 * Start the server in SSE mode (legacy, for backward compatibility)
 */
async function startSseServer(server: McpServer, host: string, port: number): Promise<void> {
    const app = express();
    app.use(express.json());
    
    // Store SSE transports by session ID
    const sseTransports: Record<string, SSEServerTransport> = {};
    
    // Legacy SSE endpoint for older clients
    app.get('/sse', async (req, res) => {
        const transport = new SSEServerTransport('/messages', res);
        sseTransports[transport.sessionId] = transport;
        
        logger.info(`SSE session created: ${transport.sessionId}`);
        
        res.on('close', () => {
            logger.info(`SSE session closed: ${transport.sessionId}`);
            delete sseTransports[transport.sessionId];
        });
        
        await server.connect(transport);
    });
    
    // Legacy message endpoint for older clients
    app.post('/messages', async (req, res) => {
        const sessionId = req.query.sessionId as string;
        const transport = sseTransports[sessionId];
        if (transport) {
            await transport.handlePostMessage(req, res, req.body);
        } else {
            res.status(400).send('No transport found for sessionId');
        }
    });
    
    // Start the server
    app.listen(port, host, () => {
        logger.info(`Frida MCP server (SSE mode) listening on http://${host}:${port}/sse`);
    }).on('error', (error) => {
        logger.error('Server error:', error);
        process.exit(1);
    });
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
        await startStreamableHttpServer(server, host, port);
    } else if (transport === 'sse') {
        logger.info(`Starting Frida MCP server in SSE mode on ${host}:${port}`);
        await startSseServer(server, host, port);
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