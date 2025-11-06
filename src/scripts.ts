/**
 * JavaScript script templates for Frida instrumentation
 * 
 * These templates use Frida's JavaScript API to perform various
 * instrumentation tasks in target processes.
 */

/**
 * Template for enumerating loaded modules in a process
 */
export const SCRIPT_ENUMERATE_MODULES = `
var modules = Process.enumerateModules();
send(modules.map(function(m) {
    return {
        name: m.name,
        base: m.base.toString(),
        size: m.size,
        path: m.path
    };
}));
`;

/**
 * Template for getting main module information
 */
export const SCRIPT_GET_MODULE_PATH = `
var mainModule = Process.enumerateModules()[0];
send({
    name: mainModule.name,
    path: mainModule.path,
    base: mainModule.base.toString(),
    size: mainModule.size
});
`;

/**
 * Template wrapper for executing JavaScript code with console.log capture
 * The {code} placeholder will be replaced with actual JavaScript code
 */
export const SCRIPT_EXECUTE_WRAPPER = `
(function() {{
    var initialLogs = [];
    var originalLog = console.log;
    
    // Intercept console.log to capture output
    console.log = function() {{
        var args = Array.prototype.slice.call(arguments);
        var logMsg = args.map(function(arg) {{
            return typeof arg === 'object' ? JSON.stringify(arg) : String(arg);
        }}).join(' ');
        initialLogs.push(logMsg);
        originalLog.apply(console, arguments);
    }};
    
    var scriptResult;
    var scriptError;
    try {{
        scriptResult = eval({code});
    }} catch (e) {{
        scriptError = {{ message: e.toString(), stack: e.stack }};
    }}
    
    // Restore console.log
    console.log = originalLog;
    
    // Send execution receipt back to TypeScript
    send({{
        type: 'execution_receipt',
        result: scriptError ? undefined : (scriptResult !== undefined ? scriptResult.toString() : 'undefined'),
        error: scriptError,
        initial_logs: initialLogs
    }});
}})();
`;

/**
 * Template for reading files in chunks
 * The {path} placeholder will be replaced with the file path
 */
export const SCRIPT_READ_FILE_CHUNKS = `
var filePath = {path};
var chunkSize = 1024 * 1024; // 1MB chunks

try {{
    var file = new File(filePath, 'rb');
    var totalSize = 0;
    var chunkIndex = 0;
    
    while (true) {{
        var chunk = file.readBytes(chunkSize);
        if (chunk.byteLength === 0) break;
        
        // Send chunk with raw binary data
        send({{
            type: 'chunk',
            index: chunkIndex,
            size: chunk.byteLength
        }}, chunk);
        
        totalSize += chunk.byteLength;
        chunkIndex++;
    }}
    
    file.close();
    
    send({{
        type: 'complete',
        status: 'success',
        totalSize: totalSize,
        chunkCount: chunkIndex
    }});
}} catch (e) {{
    send({{
        type: 'error',
        status: 'error',
        error: e.toString(),
        message: 'Failed to read file: ' + e.message
    }});
}}
`;

/**
 * Template for finding exported functions
 */
export const SCRIPT_FIND_EXPORT = `
var moduleName = {module_name};
var exportName = {export_name};

try {{
    var module = Process.findModuleByName(moduleName);
    if (!module) {{
        send({{ error: 'Module not found: ' + moduleName }});
    }} else {{
        var exportAddr = module.findExportByName(exportName);
        if (exportAddr) {{
            send({{
                found: true,
                module: moduleName,
                export: exportName,
                address: exportAddr.toString()
            }});
        }} else {{
            send({{
                found: false,
                module: moduleName,
                export: exportName,
                message: 'Export not found'
            }});
        }}
    }}
}} catch (e) {{
    send({{ error: e.toString() }});
}}
`;

/**
 * Template for reading memory at an address
 */
export const SCRIPT_READ_MEMORY = `
var address = ptr({address});
var length = {length};

try {{
    var data = Memory.readByteArray(address, length);
    send({{ success: true, length: length }}, data);
}} catch (e) {{
    send({{ success: false, error: e.toString() }});
}}
`;

/**
 * Template for writing memory at an address
 */
export const SCRIPT_WRITE_MEMORY = `
var address = ptr({address});
var data = {data};

try {{
    Memory.writeByteArray(address, data);
    send({{ success: true, bytesWritten: data.length }});
}} catch (e) {{
    send({{ success: false, error: e.toString() }});
}}
`;

/**
 * Template for enumerating exports from a module
 */
export const SCRIPT_ENUMERATE_EXPORTS = `
var moduleName = {module_name};

try {{
    var module = Process.findModuleByName(moduleName);
    if (!module) {{
        send({{ error: 'Module not found: ' + moduleName }});
    }} else {{
        var exports = module.enumerateExports();
        send({{
            module: moduleName,
            count: exports.length,
            exports: exports.map(function(exp) {{
                return {{
                    type: exp.type,
                    name: exp.name,
                    address: exp.address.toString()
                }};
            }})
        }});
    }}
}} catch (e) {{
    send({{ error: e.toString() }});
}}
`;