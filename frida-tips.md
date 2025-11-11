
# Frida Tips & Non-Obvious Features

This document highlights lesser-known but powerful Frida JavaScript API features that are particularly useful for dynamic instrumentation.

## Memory & Process Inspection

### ModuleMap for Fast Address Resolution
Instead of repeatedly calling `Process.findModuleByAddress()`, use `ModuleMap` for efficient lookups:
```javascript
const map = new ModuleMap();
const module = map.find(address);  // Much faster for repeated lookups
```

### Hardware Breakpoints & Watchpoints
Set hardware breakpoints/watchpoints on threads for precise control:
```javascript
const threads = Process.enumerateThreads();
const thread = threads[0];

// Set hardware breakpoint
thread.setHardwareBreakpoint(0, ptr('0x12345678'));

// Set hardware watchpoint for writes
thread.setHardwareWatchpoint(0, ptr('0x12345678'), 8, 'w');

// Handle with Process.setExceptionHandler()
Process.setExceptionHandler(details => {
  if (details.type === 'breakpoint') {
    console.log('Breakpoint hit at', details.address);
    return true;  // Resume execution
  }
});
```

### Memory Access Monitoring
Monitor specific memory ranges for read/write/execute access:
```javascript
MemoryAccessMonitor.enable([
  { base: ptr('0x12345000'), size: 4096 }
], {
  onAccess(details) {
    console.log(`${details.operation} at ${details.address} from ${details.from}`);
  }
});
```

## Script Management

### Script.nextTick for Deferred Execution
Execute code after the current JavaScript context exits:
```javascript
Interceptor.attach(targetFunc, {
  onEnter(args) {
    Script.nextTick(() => {
      // This runs after onEnter completes
      // Safe for potentially blocking operations
    });
  }
});
```

### Script.bindWeak for Resource Cleanup
Monitor JavaScript object lifecycle for native resource management:
```javascript
const resource = allocateNativeResource();
const jsWrapper = { resource };

Script.bindWeak(jsWrapper, () => {
  // Called when jsWrapper is garbage collected
  freeNativeResource(resource);
});
```

### Script.pin/unpin for Safe Cleanup
Prevent script unloading during critical operations:
```javascript
Script.bindWeak(obj, () => {
  Script.pin();  // Prevent unload during cleanup
  cleanupOnAnotherThread(() => {
    Script.unpin();  // Allow unload again
  });
});
```

## Interceptor Advanced Features

### Backtrace from Interceptor Context
Always pass `this.context` for accurate backtraces:
```javascript
Interceptor.attach(func, {
  onEnter(args) {
    const trace = Thread.backtrace(this.context, Backtracer.ACCURATE)
      .map(DebugSymbol.fromAddress)
      .join('\n');
    console.log('Called from:\n', trace);
  }
});
```

### Interceptor.flush for Immediate Effect
Force pending interceptor changes to take effect immediately:
```javascript
Interceptor.attach(func1, callbacks1);
Interceptor.attach(func2, callbacks2);
Interceptor.flush();  // Apply all pending changes now
```

### Replace Function Implementation Inline
Replace entire function implementation, not just hook it:
```javascript
Interceptor.replace(targetFunc, new NativeCallback((arg1, arg2) => {
  // Your complete replacement implementation
  return result;
}, 'int', ['int', 'int']));
```

## Module & Symbol Resolution

### ApiResolver for Pattern-Based Resolution
Find functions/exports matching patterns across modules:
```javascript
// Find all malloc-like functions
const resolver = new ApiResolver('module');
const matches = resolver.enumerateMatches('exports:*!*alloc*');
matches.forEach(match => {
  console.log(match.name, match.address);
});

// Objective-C methods
const objcResolver = new ApiResolver('objc');
objcResolver.enumerateMatches('-[NSURL* *HTTP*]');
```

### Module Observers for Dynamic Loading
React to module loading/unloading in real-time:
```javascript
const observer = Process.attachModuleObserver({
  onAdded(module) {
    // Called BEFORE app uses the module - perfect for instrumentation
    console.log('Loaded:', module.path);
    if (module.name === 'target.so') {
      instrumentNewModule(module);
    }
  },
  onRemoved(module) {
    console.log('Unloaded:', module.path);
  }
});
```

## Thread Management

### Process.runOnThread for Cross-Thread Execution
Execute code on a specific thread (use with caution):
```javascript
const threadId = Process.getCurrentThreadId();
Process.runOnThread(threadId, () => {
  // Runs on specified thread
  return someValue;
}).then(result => {
  console.log('Result from thread:', result);
});
```

### Thread Observers
Monitor thread lifecycle events:
```javascript
const observer = Process.attachThreadObserver({
  onAdded(thread) {
    console.log('Thread created:', thread.id, thread.name);
  },
  onRenamed(thread, previousName) {
    console.log('Thread renamed:', previousName, '->', thread.name);
  },
  onRemoved(thread) {
    console.log('Thread exiting:', thread.id);
  }
});
```

## Advanced Memory Operations

### Memory.scan for Pattern Search
Search memory for byte patterns:
```javascript
Memory.scan(module.base, module.size, 'ff 25 ?? ?? ?? ??', {
  onMatch(address, size) {
    console.log('Pattern found at', address);
  },
  onComplete() {
    console.log('Scan complete');
  }
});
```

### Memory.copy vs Memory.dup
- `Memory.copy(dst, src, size)`: Fast in-place copy
- `Memory.dup(mem, size)`: Allocate and copy (returns new ArrayBuffer)

### CModule for C Performance
Compile C code for performance-critical operations:
```javascript
const cm = new CModule(`
  #include <gum/guminterceptor.h>
  
  int fast_computation(int x) {
    return x * x + 42;
  }
  
  void export_compute(GumInvocationContext *ctx) {
    int arg = (int)gum_invocation_context_get_nth_argument(ctx, 0);
    gum_invocation_context_replace_return_value(ctx, GSIZE_TO_POINTER(fast_computation(arg)));
  }
`);

Interceptor.attach(targetFunc, cm.export_compute);
```

## Stalker for Instruction-Level Tracing

### Basic Code Tracing
```javascript
Stalker.follow(threadId, {
  events: {
    call: true,    // Log all calls
    ret: true,     // Log all returns
    exec: false,   // Log every instruction (very verbose!)
  },
  onReceive(events) {
    console.log('Events:', Stalker.parse(events));
  }
});
```

### Stalker with Transformers
Modify instruction stream on-the-fly:
```javascript
Stalker.follow(threadId, {
  transform(iterator) {
    let instruction = iterator.next();
    do {
      // Keep all instructions
      iterator.keep();
      
      // Add custom instrumentation before calls
      if (instruction.mnemonic === 'call') {
        iterator.putCallout(context => {
          console.log('About to call:', instruction.operands[0]);
        });
      }
    } while ((instruction = iterator.next()) !== null);
  }
});
```

## Exception Handling

### Global Exception Handler
Catch and handle native exceptions before the OS:
```javascript
Process.setExceptionHandler(details => {
  console.
```javascript
Process.setExceptionHandler(details => {
  console.log('Exception:', details.type, 'at', details.address);
  
  // Access violation details
  if (details.memory) {
    console.log(`${details.memory.operation} at ${details.memory.address}`);
  }
  
  // Modify registers to recover
  details.context.pc = ptr('0x12345678');  // Change execution flow
  
  return true;  // Return true to handle and resume
});
```

## Cloak API for Stealth

### Hide Threads from Enumeration
```javascript
Cloak.addThread(threadId);  // Hide thread from Process.enumerateThreads()
Cloak.removeThread(threadId);  // Unhide
```

### Hide Memory Ranges
```javascript
Cloak.addRange(range);  // Hide from Process.enumerateRanges()
Cloak.removeRange(range);
```

### Hide File Descriptors
```javascript
Cloak.addFileDescriptor(fd);  // Hide from enumeration
Cloak.removeFileDescriptor(fd);
```

## Communication Between Host and Script

### send() with Binary Data
```javascript
// Send binary data efficiently
const buffer = new ArrayBuffer(1024);
send({ type: 'data' }, buffer);  // Second argument is sent as binary
```

### recv() for Synchronous Communication
```javascript
recv('input', message => {
  console.log('Received:', message);
});

// From Python host:
// script.post({'type': 'input', 'payload': 'data'})
```

## Performance Tips

### Avoid Repeated Module Lookups
```javascript
// ❌ Slow - lookups on every call
Interceptor.attach(Module.getExportByName('libc.so', 'malloc'), ...);

// ✅ Fast - lookup once
const mallocAddr = Module.getExportByName('libc.so', 'malloc');
Interceptor.attach(mallocAddr, ...);
```

### Use NativeFunction for Frequent Calls
```javascript
// ❌ Slow - repeated function parsing
Memory.readPointer(addr);
Memory.readPointer(addr);

// ✅ Fast - parse once, call many times
const myFunc = new NativeFunction(funcAddr, 'int', ['pointer', 'int']);
myFunc(ptr('0x1234'), 42);
```

### Batch Memory Operations
```javascript
// ❌ Slow - multiple small operations
for (let i = 0; i < 100; i++) {
  Memory.writeU32(addr.add(i * 4), values[i]);
}

// ✅ Fast - single bulk write
Memory.writeByteArray(addr, new Uint32Array(values));
```

## Socket Operations

### Create TCP Server for Remote Control
```javascript
Socket.listen({
  family: 'ipv4',
  port: 12345
}, {
  onConnection(connection) {
    console.log('Client connected');
    connection.input.read(1024).then(buffer => {
      const command = buffer.toString();
      // Execute command and send response
      connection.output.write(new TextEncoder().encode(response));
    });
  }
});
```

## File Operations

### Efficient File Reading
```javascript
const file = new File('/path/to/file', 'rb');
const stream = new UnixInputStream(file.handle);
stream.read(1024).then(buffer => {
  console.log('Read', buffer.byteLength, 'bytes');
  file.close();
});
```

### SQLite Database Access
```javascript
const db = SqliteDatabase.open('/data/data/com.app/databases/app.db');
const stmt = db.prepare('SELECT * FROM users WHERE id = ?');
stmt.bindInteger(1, 42);

while (stmt.step()) {
  console.log('User:', stmt.getString(1), stmt.getInteger(2));
}
stmt.reset();
db.close();
```

## Worker Threads

### Offload Heavy Computation
```javascript
const worker = new Worker('worker.js');
worker.post({ cmd: 'compute', data: largeDataset });
worker.message.connect(message => {
  console.log('Worker result:', message);
});
```

## Best Practices

### Always Check Process.codeSigningPolicy
```javascript
if (Process.codeSigningPolicy === 'required') {
  console.warn('Code signing required - cannot use Interceptor or modify code');
  // Use alternative instrumentation methods
}
```

### Use Process.pageSize for Portable Code
```javascript
// ❌ Hard-coded page size
const alignment = 4096;

// ✅ Portable across platforms
const alignment = Process.pageSize;
```

### Cleanup Resources Properly
```javascript
const listener = Interceptor.attach(func, callbacks);

// Later, when done:
listener.detach();  // Remove hook

// For observers:
const observer = Process.attachModuleObserver(callbacks);
observer.detach();  // Stop observing
```

## Debugging Tips

### Enable Verbose Logging
```javascript
// In your script
console.log('Debug info:', JSON.stringify(obj, null, 2));

// Use hexdump for binary data
console.log(hexdump(buffer, { ansi: true }));
```

### Source Maps for Better Stack Traces
```javascript
// Register source map for your compiled script
Script.registerSourceMap('/agent.js', sourceMapJson);

// Now errors show original TypeScript line numbers
```

## Platform-Specific Tips

### Windows: Use SystemFunction
```javascript
const kernel32 = Process.getModuleByName('kernel32.dll');
const GetCurrentThreadId = new SystemFunction(
  kernel32.getExportByName('GetCurrentThreadId'),
  'uint32', []
);
const tid = GetCurrentThreadId();
```

### iOS/macOS: ObjC Block Handling
```javascript
const block = new ObjC.Block(blockPtr);
console.log('Block signature:', block.signature);
const impl = block.implementation;  // Get native function
```

### Android: Java Class Loading
```javascript
Java.perform(() => {
  const ActivityThread = Java.use('android.app.ActivityThread');
  const currentApp = ActivityThread.currentApplication();
  const context = currentApp.getApplicationContext();
  
  // Now you can use context for Android APIs
});
```