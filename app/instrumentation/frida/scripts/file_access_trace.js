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
  '.openclaw',
  '/tmp/openclaw/uploads',
];

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

function isSensitive(path) {
  if (!path) return false;
  var lower = path.toLowerCase();
  return SENSITIVE_FRAGMENTS.some(function (frag) { return lower.indexOf(frag) !== -1; });
}

// ---------------------------------------------------------------------------
// libc open()
// ---------------------------------------------------------------------------

function installOpen() {
  var modules = ['libsystem_kernel.dylib', 'libc.so.6', 'libc.so', null];
  modules.forEach(function (mod) {
    try {
      var addr = Module.findExportByName(mod, 'open');
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          try {
            this.path = args[0].readUtf8String();
          } catch (_) {
            this.path = null;
          }
          this.flags = args[1].toInt32();
          this.shouldEmit = isSensitive(this.path);
        },
        onLeave: function (retval) {
          if (!this.shouldEmit) return;
          emit('file_open', {
            path: this.path,
            flags: this.flags,
            fd: retval.toInt32(),
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
  modules.forEach(function (mod) {
    try {
      var addr = Module.findExportByName(mod, 'read');
      if (!addr) return;
      Interceptor.attach(addr, {
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
            fd: this.fd,
            bytesRead: bytesRead,
            previewAscii: preview,
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
  modules.forEach(function (mod) {
    try {
      var addr = Module.findExportByName(mod, 'write');
      if (!addr) return;
      Interceptor.attach(addr, {
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
            fd: this.fd,
            bytesWritten: bytesWritten,
            previewAscii: this.preview,
          });
        },
      });
    } catch (_) { }
  });
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

installOpen();
installRead();
installWrite();

emit('frida_ready', {
  message: 'file_access_trace.js libc hooks installed (experimental)',
  experimental: true,
});
