/**
 * Logging utility for Frida MCP Server
 */

export class Logger {
    private name: string;
    
    constructor(name: string) {
        this.name = name;
    }
    
    private formatMessage(level: string, message: string): string {
        const timestamp = new Date().toISOString();
        return `[${timestamp}] ${level} [${this.name}] ${message}`;
    }
    
    info(message: string): void {
        console.error(this.formatMessage('INFO', message));
    }
    
    debug(message: string): void {
        console.error(this.formatMessage('DEBUG', message));
    }
    
    warning(message: string): void {
        console.error(this.formatMessage('WARNING', message));
    }
    
    error(message: string, error?: Error): void {
        let msg = this.formatMessage('ERROR', message);
        if (error) {
            msg += `\n${error.stack || error.message}`;
        }
        console.error(msg);
    }
}

export const logger = new Logger('frida-mcp');