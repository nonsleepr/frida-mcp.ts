/**
 * JavaScript script templates for Frida instrumentation
 * 
 * These templates use Frida's JavaScript API to perform various
 * instrumentation tasks in target processes.
 */

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
 * REMOVED: Script wrapper is no longer used.
 * Scripts now execute directly without wrapping to preserve correct line numbers.
 *
 * Console interception is now handled by a separate persistent script loaded
 * at session creation to avoid affecting user script line numbers.
 */

/**
 * Console interceptor script that captures console.* output via send()
 * Compact single-line version to minimize impact on line numbers.
 * Returns objects as-is without stringification for better structure preservation.
 */
export const CONSOLE_INTERCEPTOR = `(function(){var methods=['log','error','warn','info','debug'];methods.forEach(function(method){var original=console[method];console[method]=function(){var args=Array.prototype.slice.call(arguments);if(args.length===1){send({type:'console.'+method,message:args[0]});}else if(args.length>1){send({type:'console.'+method,message:args});}original.apply(console,arguments);};});})();`;

/**
 * Template for reading files in chunks
 * The {path} placeholder will be replaced with the file path
 */
export const SCRIPT_READ_FILE_CHUNKS = `
var filePath = {path};
var chunkSize = 1024 * 1024; // 1MB chunks

try {
    var file = new File(filePath, 'rb');
    var totalSize = 0;
    var chunkIndex = 0;
    
    while (true) {
        var chunk = file.readBytes(chunkSize);
        if (chunk.byteLength === 0) break;
        
        // Send chunk with raw binary data
        send({
            type: 'chunk',
            index: chunkIndex,
            size: chunk.byteLength
        }, chunk);
        
        totalSize += chunk.byteLength;
        chunkIndex++;
    }
    
    file.close();
    
    send({
        type: 'complete',
        status: 'success',
        totalSize: totalSize,
        chunkCount: chunkIndex
    });
} catch (e) {
    send({
        type: 'error',
        status: 'error',
        error: e.toString(),
        message: 'Failed to read file: ' + e.message
    });
}
`;