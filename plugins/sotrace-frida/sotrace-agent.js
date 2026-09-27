'use strict';
/**
 * sotrace-agent.js — Frida instrumentation script for sotrace-database.
 *
 * Inject into a target process:
 *   frida -U -f com.example.app --load sotrace-agent.js
 *   frida -U com.example.app    --load sotrace-agent.js   # attach to running
 *
 * Configure via rpc.exports.configure() from the host script, or set defaults
 * below.  All data is shipped to the host via Frida's send() / on('message').
 */

// ---------------------------------------------------------------------------
// Default configuration (overridden at runtime via rpc.exports.configure)
// ---------------------------------------------------------------------------
const cfg = {
  soBase: 0,                  // SO runtime base address (for offset calc). 0 = no adjust
  soSize: 0x10000000,         // Range to track around soBase.  Ignored when soBase=0
  enableInstructions: false,  // exec-level tracing is expensive; off by default
  enableMemory: true,         // memory read/write hooks
  enableSync: true,           // pthread mutex / condvar / rwlock hooks
  enableCalls: true,          // call / return via Stalker events
  batchSize: 500,             // max events per send() call
  flushIntervalMs: 500,       // periodic flush even if batch not full
  traceId: 0,                 // 0 = server auto-assigns on first import
};

// ---------------------------------------------------------------------------
// Event buffer
// ---------------------------------------------------------------------------
const buf = {
  instructions: [],
  memoryWrites: [],
  memoryReads: [],
  syncEvents: [],
  calls: [],
};
let seq = 0;
let flushTimer = null;

function nextSeq() { return ++seq; }

function bufSize() {
  return buf.instructions.length + buf.memoryWrites.length +
    buf.memoryReads.length + buf.syncEvents.length + buf.calls.length;
}

function flush() {
  if (bufSize() === 0) return;
  const payload = {
    type: 'sotrace:batch',
    traceId: cfg.traceId,
    instructions: buf.instructions.splice(0),
    memoryWrites: buf.memoryWrites.splice(0),
    memoryReads: buf.memoryReads.splice(0),
    syncEvents: buf.syncEvents.splice(0),
    calls: buf.calls.splice(0),
  };
  send(payload);
}

function maybeFlush() {
  if (bufSize() >= cfg.batchSize) flush();
}

function startFlushTimer() {
  if (flushTimer !== null) return;
  flushTimer = setInterval(flush, cfg.flushIntervalMs);
}

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------
function toSoOffset(addr) {
  if (cfg.soBase === 0) return addr;
  const offset = addr - cfg.soBase;
  return (offset >= 0 && offset < cfg.soSize) ? offset : addr;
}

function isArm64() {
  return Process.arch === 'arm64';
}

// ---------------------------------------------------------------------------
// Stalker (instruction + call/ret tracing)
// ---------------------------------------------------------------------------
const trackedThreads = new Set();

function followThread(tid) {
  if (trackedThreads.has(tid)) return;
  trackedThreads.add(tid);

  const stalkerOpts = {
    events: {
      call: cfg.enableCalls,
      ret: cfg.enableCalls,
      exec: cfg.enableInstructions,
      block: false,
      compile: false,
    },
    onReceive(rawEvents) {
      const parsed = Stalker.parse(rawEvents, {
        annotate: true,
        stringify: false,
      });
      let depth = 0;
      for (const ev of parsed) {
        const kind = ev[0]; // 'call', 'ret', 'exec', ...
        if (kind === 'call') {
          const location = ev[1] ? ev[1].sub(1) : ptr(0); // return addr - 1 ≈ call site
          const target   = ev[2] || ptr(0);
          buf.calls.push({
            seq: nextSeq(),
            tid: tid,
            caller: toSoOffset(location.toUInt32()),
            callee: toSoOffset(target.toUInt32()),
            depth: depth,
            event_type: 'Call',
          });
          depth++;
          maybeFlush();
        } else if (kind === 'ret') {
          if (depth > 0) depth--;
          const location = ev[1] || ptr(0);
          const target   = ev[2] || ptr(0);
          buf.calls.push({
            seq: nextSeq(),
            tid: tid,
            caller: toSoOffset(location.toUInt32()),
            callee: toSoOffset(target.toUInt32()),
            depth: depth,
            event_type: 'Return',
          });
          maybeFlush();
        } else if (kind === 'exec') {
          const addr = ev[1] || ptr(0);
          buf.instructions.push({
            seq: nextSeq(),
            tid: tid,
            address: toSoOffset(addr.toUInt32()),
            is_branch: false,
            branch_taken: false,
          });
          maybeFlush();
        }
      }
    },
  };

  try {
    Stalker.follow(tid, stalkerOpts);
  } catch (e) {
    // Stalker may not be available on all platforms; degrade gracefully
    console.warn('[sotrace] Stalker.follow failed for tid=' + tid + ': ' + e.message);
    trackedThreads.delete(tid);
  }
}

// ---------------------------------------------------------------------------
// Memory hooks (Interceptor-based MemoryAccessMonitor)
// ---------------------------------------------------------------------------
function installMemoryHooks() {
  if (!cfg.enableMemory) return;
  if (typeof MemoryAccessMonitor === 'undefined') {
    console.warn('[sotrace] MemoryAccessMonitor not available on this platform');
    return;
  }

  // MemoryAccessMonitor is available on certain Frida builds; fall back to
  // Stalker transform for production use.  We use a lightweight approach here:
  // hook libc's memcpy/memmove to catch bulk writes, and rely on Stalker's
  // exec events for fine-grained access tracking when enableInstructions=true.

  const captureMemWrite = (fnName) => {
    const sym = Module.findExportByName(null, fnName);
    if (!sym) return;
    Interceptor.attach(sym, {
      onEnter(args) {
        this._dst = args[0];
        this._size = args[2].toUInt32();
        this._tid = Process.getCurrentThreadId();
      },
      onLeave() {
        if (!this._dst || this._size === 0) return;
        try {
          const addr = this._dst.toUInt32();
          const bytes = Array.from(this._dst.readByteArray(Math.min(this._size, 64)) || []);
          buf.memoryWrites.push({ step: nextSeq(), tid: this._tid, address: toSoOffset(addr), data: bytes });
          maybeFlush();
        } catch (_) {}
      },
    });
  };

  captureMemWrite('memcpy');
  captureMemWrite('memmove');
}

// ---------------------------------------------------------------------------
// Sync event hooks (pthread_mutex_*, pthread_rwlock_*, pthread_cond_*)
// ---------------------------------------------------------------------------
const SYNC_MAP = {
  pthread_mutex_lock:      { syncType: 'MutexLock',         result: 'Success' },
  pthread_mutex_unlock:    { syncType: 'MutexUnlock',        result: 'Success' },
  pthread_mutex_trylock:   { syncType: 'MutexTryLock',       result: 'Success' },
  pthread_mutex_timedlock: { syncType: 'MutexLock',          result: 'Success' },
  pthread_rwlock_rdlock:   { syncType: 'RwLockRead',         result: 'Success' },
  pthread_rwlock_wrlock:   { syncType: 'RwLockWrite',        result: 'Success' },
  pthread_rwlock_unlock:   { syncType: 'RwLockUnlock',       result: 'Success' },
  pthread_cond_wait:       { syncType: 'CondvarWait',        result: 'Success' },
  pthread_cond_signal:     { syncType: 'CondvarSignal',      result: 'Success' },
  pthread_cond_broadcast:  { syncType: 'CondvarBroadcast',   result: 'Success' },
};

function installSyncHooks() {
  if (!cfg.enableSync) return;
  for (const [symName, { syncType, result }] of Object.entries(SYNC_MAP)) {
    const sym = Module.findExportByName(null, symName);
    if (!sym) continue;
    try {
      Interceptor.attach(sym, {
        onEnter(args) {
          const tid = Process.getCurrentThreadId();
          // First argument is the mutex / condvar / rwlock pointer
          const objAddr = args[0] ? args[0].toUInt32() : 0;
          const s = nextSeq();
          buf.syncEvents.push({ step: s, tid, sync_type: syncType, sync_object_addr: objAddr, result });
          maybeFlush();

          // Also start Stalker tracing for this thread if not already done
          if (cfg.enableCalls || cfg.enableInstructions) {
            followThread(tid);
          }
        },
      });
    } catch (e) {
      console.warn('[sotrace] Could not hook ' + symName + ': ' + e.message);
    }
  }
}

// ---------------------------------------------------------------------------
// JNI hooks (basic — hooks JNI_OnLoad as a sentinel)
// ---------------------------------------------------------------------------
function installJniHooks() {
  const sym = Module.findExportByName(null, 'JNI_OnLoad');
  if (!sym) return;
  Interceptor.attach(sym, {
    onEnter() {
      const tid = Process.getCurrentThreadId();
      followThread(tid);
    },
  });
}

// ---------------------------------------------------------------------------
// Thread tracking — follow new threads automatically
// ---------------------------------------------------------------------------
function trackMainThread() {
  const tid = Process.getCurrentThreadId();
  if (cfg.enableCalls || cfg.enableInstructions) {
    followThread(tid);
  }
}

// ---------------------------------------------------------------------------
// rpc.exports — called from the Python host script
// ---------------------------------------------------------------------------
rpc.exports = {
  /**
   * Apply configuration.  Call this before the target function executes.
   *
   * @param {object} options - Configuration overrides
   * @param {number} [options.soBase]              - SO base address (number or hex string)
   * @param {number} [options.soSize]              - Tracked address range size
   * @param {boolean} [options.enableInstructions] - Enable exec-level tracing
   * @param {boolean} [options.enableMemory]       - Enable memory hooks
   * @param {boolean} [options.enableSync]         - Enable pthread sync hooks
   * @param {boolean} [options.enableCalls]        - Enable call/ret via Stalker
   * @param {number}  [options.batchSize]          - Events per send() batch
   * @param {number}  [options.flushIntervalMs]    - Periodic flush interval (ms)
   * @param {number}  [options.traceId]            - sotrace trace ID (0 = server assigns)
   */
  configure(options) {
    if (options.soBase !== undefined) {
      cfg.soBase = typeof options.soBase === 'string'
        ? parseInt(options.soBase, 16)
        : options.soBase;
    }
    if (options.soSize !== undefined)              cfg.soSize = options.soSize;
    if (options.enableInstructions !== undefined)  cfg.enableInstructions = !!options.enableInstructions;
    if (options.enableMemory !== undefined)        cfg.enableMemory = !!options.enableMemory;
    if (options.enableSync !== undefined)          cfg.enableSync = !!options.enableSync;
    if (options.enableCalls !== undefined)         cfg.enableCalls = !!options.enableCalls;
    if (options.batchSize !== undefined)           cfg.batchSize = options.batchSize;
    if (options.flushIntervalMs !== undefined)     cfg.flushIntervalMs = options.flushIntervalMs;
    if (options.traceId !== undefined)             cfg.traceId = options.traceId;
    return 'configured';
  },

  /** Update the traceId after the server assigns one. */
  setTraceId(id) {
    cfg.traceId = id;
  },

  /** Force-flush the current buffer. */
  flush() {
    flush();
    return bufSize();
  },

  /** List all modules loaded in the target process. */
  listModules() {
    return Process.enumerateModules().map(m => ({
      name: m.name,
      base: m.base.toString(),
      size: m.size,
      path: m.path,
    }));
  },

  /** Return current configuration. */
  getConfig() {
    return Object.assign({}, cfg);
  },
};

// ---------------------------------------------------------------------------
// Initialisation
// ---------------------------------------------------------------------------
(function init() {
  installSyncHooks();
  installMemoryHooks();
  installJniHooks();
  trackMainThread();
  startFlushTimer();
  console.log('[sotrace] Agent initialised. arch=' + Process.arch +
    '  pid=' + Process.id +
    '  enableCalls=' + cfg.enableCalls +
    '  enableInstructions=' + cfg.enableInstructions +
    '  enableSync=' + cfg.enableSync);
})();
