'use strict';
/*
 * file_access_trace.js — EXPERIMENTAL libc-level file access hooks
 *
 * Hooks libc open() / read() / write() to detect sensitive file accesses
 * independent of Node.js fs wrappers (e.g. credential theft, upload staging).
 *
 * ⚠ EXPERIMENTAL — high event volume in production; use with care.
 */

var SENSITIVE_FRAGMENTS = [
  '.ssh',
  '.env',
  'id_rsa',
  'id_ed25519',
  'token',
  'credential',
  'key',
  '/tmp/openclaw/uploads',
];

var ATTACHED_ADDRESSES = {};

function nowIso() {
  return new Date().toISOString();
}

function emit(kind, payload) {
  send({
    type: 'trace',
    ts: nowIso(),
    pid: Process.id,
    kind: kind,
    payload: payload,
  });
}

function findExport(moduleName, symbolName) {
  try {
    if (typeof Module.findExportByName === 'function') {
      var byModule = Module.findExportByName(moduleName, symbolName);
      if (byModule) return byModule;
    }
  } catch (_) { }
  try {
    if (typeof Module.findGlobalExportByName === 'function') {
      return Module.findGlobalExportByName(symbolName);
    }
  } catch (_) { }
  return null;
}

function isSensitive(path) {
  if (!path) return false;
  var lower = path.toLowerCase();
  return SENSITIVE_FRAGMENTS.some(function (frag) { return lower.indexOf(frag) !== -1; });
}

function attachOnce(addr, callbacks) {
  if (!addr) return false;
  var key = String(addr);
  if (ATTACHED_ADDRESSES[key]) return false;
  Interceptor.attach(addr, callbacks);
  ATTACHED_ADDRESSES[key] = true;
  return true;
}

// ---------------------------------------------------------------------------
// libc open()
// ---------------------------------------------------------------------------

function installOpen() {
  var modules = ['libsystem_kernel.dylib', 'libc.so.6', 'libc.so', null];
  var specs = [
    { name: 'open', pathArg: 0, flagsArg: 1 },
    { name: 'open$NOCANCEL', pathArg: 0, flagsArg: 1 },
    { name: 'openat', pathArg: 1, flagsArg: 2 },
    { name: 'openat$NOCANCEL', pathArg: 1, flagsArg: 2 },
  ];
  modules.forEach(function (mod) {
    specs.forEach(function (spec) {
      try {
        var addr = findExport(mod, spec.name);
        if (!addr) return;
        attachOnce(addr, {
          onEnter: function (args) {
            try {
              this.path = args[spec.pathArg].readUtf8String();
            } catch (_) {
              this.path = null;
            }
            this.flags = args[spec.flagsArg].toInt32();
            this.shouldEmit = isSensitive(this.path);
          },
          onLeave: function (retval) {
            if (!this.shouldEmit) return;
            emit('file_open', {
              api: spec.name,
              path: this.path,
              flags: this.flags,
              fd: retval.toInt32(),
            });
          },
        });
      } catch (_) { }
    });
  });
}

// ---------------------------------------------------------------------------
// libc close()
// ---------------------------------------------------------------------------

function installClose() {
  var modules = ['libsystem_kernel.dylib', 'libc.so.6', 'libc.so', null];
  modules.forEach(function (mod) {
    try {
      var addr = findExport(mod, 'close');
      if (!addr) return;
      attachOnce(addr, {
        onEnter: function (args) {
          this.fd = args[0].toInt32();
        },
        onLeave: function (retval) {
          var result = retval.toInt32();
          if (result !== 0) return;
          emit('file_close', {
            api: 'close',
            fd: this.fd,
          });
        },
      });
    } catch (_) { }
  });
}

// ---------------------------------------------------------------------------
// libc read()
// ---------------------------------------------------------------------------

function installRead() {
  var modules = ['libsystem_c.dylib', 'libc.so.6', 'libc.so', null];
  var symbols = ['read', 'read$NOCANCEL'];
  modules.forEach(function (mod) {
    symbols.forEach(function (symbol) {
      try {
        var addr = findExport(mod, symbol);
        if (!addr) return;
        attachOnce(addr, {
          onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.buf = args[1];
            this.count = args[2].toInt32();
          },
          onLeave: function (retval) {
            var bytesRead = retval.toInt32();
            if (bytesRead <= 0) return;
            // We emit read events only for small reads (likely config / credential files)
            if (bytesRead > 8192) return;
            var preview = '';
            try {
              var size = Math.min(bytesRead, 128);
              var bytes = this.buf.readByteArray(size);
              var view = new Uint8Array(bytes);
              preview = Array.from(view).map(function (b) { return (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.'; }).join('');
            } catch (_) { }
            emit('file_read', {
              api: symbol,
              fd: this.fd,
              bytesRead: bytesRead,
              previewAscii: preview,
            });
          },
        });
      } catch (_) { }
    });
  });
}

// ---------------------------------------------------------------------------
// libc connect()
// ---------------------------------------------------------------------------

function installConnect() {
  var modules = ['libsystem_kernel.dylib', 'libc.so.6', 'libc.so', null];
  modules.forEach(function (mod) {
    try {
      var addr = findExport(mod, 'connect');
      if (!addr) return;
      attachOnce(addr, {
        onEnter: function (args) {
          this.fd = args[0].toInt32();
        },
        onLeave: function (retval) {
          if (retval.toInt32() !== 0) return;
          emit('socket_connect', {
            api: 'connect',
            fd: this.fd,
          });
        },
      });
    } catch (_) { }
  });
}

// ---------------------------------------------------------------------------
// libc write()
// ---------------------------------------------------------------------------

function installWrite() {
  var modules = ['libsystem_c.dylib', 'libc.so.6', 'libc.so', null];
  var symbols = ['write', 'write$NOCANCEL'];
  modules.forEach(function (mod) {
    symbols.forEach(function (symbol) {
      try {
        var addr = findExport(mod, symbol);
        if (!addr) return;
        attachOnce(addr, {
          onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.count = args[2].toInt32();
            // Only trace small writes to reduce noise.
            if (this.count > 0 && this.count <= 4096) {
              try {
                var size = Math.min(this.count, 128);
                var bytes = args[1].readByteArray(size);
                var view = new Uint8Array(bytes);
                this.preview = Array.from(view).map(function (b) { return (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.'; }).join('');
              } catch (_) {
                this.preview = '';
              }
            } else {
              this.preview = null;
            }
          },
          onLeave: function (retval) {
            if (this.preview === null) return;
            var bytesWritten = retval.toInt32();
            if (bytesWritten <= 0) return;
            emit('file_write', {
              api: symbol,
              fd: this.fd,
              bytesWritten: bytesWritten,
              previewAscii: this.preview,
            });
          },
        });
      } catch (_) { }
    });
  });
}

// ---------------------------------------------------------------------------
// libc send()
// ---------------------------------------------------------------------------

function installSend() {
  var modules = ['libsystem_kernel.dylib', 'libc.so.6', 'libc.so', null];
  var symbols = ['send', 'sendto'];
  modules.forEach(function (mod) {
    symbols.forEach(function (symbol) {
      try {
        var addr = findExport(mod, symbol);
        if (!addr) return;
        attachOnce(addr, {
          onEnter: function (args) {
            this.fd = args[0].toInt32();
            this.count = args[2].toInt32();
          },
          onLeave: function (retval) {
            var bytesSent = retval.toInt32();
            if (bytesSent <= 0) return;
            emit('socket_send', {
              api: symbol,
              fd: this.fd,
              bytesSent: bytesSent,
              requestedBytes: this.count,
            });
          },
        });
      } catch (_) { }
    });
  });
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

installOpen();
installRead();
installWrite();
installClose();
installConnect();
installSend();

emit('frida_ready', {
  message: 'file_access_trace.js libc hooks installed (experimental)',
  experimental: true,
});
