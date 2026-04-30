'use strict';
/*
 * chrome_network_trace.js — EXPERIMENTAL best-effort Frida hook for Chrome/Chromium
 *
 * Chrome's multi-process architecture makes deep network-stack hooking fragile.
 * This script provides:
 *   1. Process attach / ready confirmation
 *   2. libc connect() observation (best-effort, may miss TLS-internal calls)
 *   3. libc send() observation for POST / upload detection via ASCII preview
 *
 * ⚠ EXPERIMENTAL — not a replacement for Playwright/CDP/server_events evidence.
 */

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

function summarizeBytes(ptr, length) {
  var requested = Number(length || 0);
  if (!ptr || ptr.isNull() || !requested) {
    return { length: requested, previewHex: '', previewAscii: '' };
  }
  var size = Math.min(requested, 128);
  try {
    var bytes = ptr.readByteArray(size);
    var view = new Uint8Array(bytes);
    var hex = Array.from(view).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    var ascii = Array.from(view).map(function (b) { return (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.'; }).join('');
    return { length: requested, previewHex: hex, previewAscii: ascii };
  } catch (_) {
    return { length: requested, previewHex: '', previewAscii: '' };
  }
}

// ---------------------------------------------------------------------------
// 1. libc connect()
// ---------------------------------------------------------------------------

function installConnect() {
  var modules = ['libsystem_c.dylib', 'libc.so.6', 'libc.so', null];
  modules.forEach(function (mod) {
    try {
      var addr = Module.findExportByName(mod, 'connect');
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          this.fd = args[0].toInt32();
          try {
            var sa = args[1];
            var family = sa.readU8();
            if (family === 2) {
              // AF_INET
              var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
              var ip = [sa.add(4).readU8(), sa.add(5).readU8(), sa.add(6).readU8(), sa.add(7).readU8()].join('.');
              this.remote = { family: 'ipv4', ip: ip, port: port };
            } else {
              this.remote = { family: 'af_' + family };
            }
          } catch (_) {
            this.remote = null;
          }
        },
        onLeave: function (retval) {
          if (!this.remote) return;
          emit('socket_connect', {
            api: 'libc.connect',
            socket: String(this.fd),
            remoteIp: this.remote.ip || null,
            remotePort: this.remote.port || null,
            family: this.remote.family || null,
          });
        },
      });
    } catch (_) { }
  });
}

// ---------------------------------------------------------------------------
// 2. libc send() — capture body preview for POST / upload scanning
// ---------------------------------------------------------------------------

function installSend() {
  var modules = ['libsystem_c.dylib', 'libc.so.6', 'libc.so', null];
  modules.forEach(function (mod) {
    try {
      var addr = Module.findExportByName(mod, 'send');
      if (!addr) return;
      Interceptor.attach(addr, {
        onEnter: function (args) {
          this.fd = args[0].toInt32();
          this.length = args[2].toInt32();
          this.summary = summarizeBytes(args[1], this.length);
        },
        onLeave: function (retval) {
          var sent = retval.toInt32();
          if (sent <= 0) return;
          emit('socket_send', {
            api: 'libc.send',
            socket: String(this.fd),
            bytesRequested: this.length,
            bytesSent: sent,
            previewHex: this.summary.previewHex,
            previewAscii: this.summary.previewAscii,
          });
        },
      });
    } catch (_) { }
  });
}

// ---------------------------------------------------------------------------
// Install hooks
// ---------------------------------------------------------------------------

installConnect();
installSend();

emit('frida_ready', {
  message: 'chrome_network_trace.js hooks installed (experimental)',
  experimental: true,
});
