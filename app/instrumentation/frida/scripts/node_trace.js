'use strict';
/*
 * node_trace.js — Frida hook script for OpenClaw gateway / Node.js processes
 *
 * Hooks:
 *   1. child_process  — exec, execFile, spawn, fork
 *   2. fs             — readFile, writeFile, open, stat, access, createReadStream, createWriteStream
 *   3. http / https   — request / globalThis.fetch
 *
 * All events are sent via Frida `send()` and consumed by FridaTraceManager.
 */

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function nowIso() {
  return new Date().toISOString();
}

function truncate(value, maxLen) {
  maxLen = maxLen || 2048;
  if (typeof value !== 'string') {
    try { value = JSON.stringify(value); } catch (_) { value = String(value); }
  }
  return value.length > maxLen ? value.slice(0, maxLen) + '...(truncated)' : value;
}

function safeHeaderKeys(headers) {
  if (!headers || typeof headers !== 'object') return [];
  return Object.keys(headers);
}

function emit(kind, payload) {
  send({
    type: 'trace',
    ts: nowIso(),
    pid: typeof Process !== 'undefined' ? Process.id : null,
    kind: kind,
    payload: payload,
  });
}

// ---------------------------------------------------------------------------
// 1. child_process hooks
// ---------------------------------------------------------------------------

function hookChildProcess() {
  try {
    var cp = require('child_process');

    ['exec', 'execFile', 'spawn', 'fork'].forEach(function (fn) {
      if (typeof cp[fn] !== 'function') return;
      var original = cp[fn];
      cp[fn] = function () {
        var args = Array.prototype.slice.call(arguments);
        var command = typeof args[0] === 'string' ? args[0] : '';
        var fnArgs = Array.isArray(args[1]) ? args[1] : [];
        var options = (typeof args[1] === 'object' && !Array.isArray(args[1])) ? args[1] : (typeof args[2] === 'object' ? args[2] : {});
        emit('process_spawn', {
          api: 'child_process.' + fn,
          command: command,
          commandLine: command + ' ' + fnArgs.join(' '),
          args: fnArgs,
          cwd: options.cwd || null,
          success: true,
        });
        return original.apply(cp, arguments);
      };
    });
  } catch (_) {
    // child_process may not be available
  }
}

// ---------------------------------------------------------------------------
// 2. fs hooks
// ---------------------------------------------------------------------------

function hookFs() {
  try {
    var fs = require('fs');

    var fsOps = ['readFile', 'writeFile', 'open', 'stat', 'access'];
    fsOps.forEach(function (op) {
      if (typeof fs[op] !== 'function') return;
      var original = fs[op];
      fs[op] = function () {
        var filePath = typeof arguments[0] === 'string' ? arguments[0] : String(arguments[0] || '');
        emit('file_' + (op === 'readFile' ? 'read' : op === 'writeFile' ? 'write' : op), {
          path: filePath,
          operation: op,
          flags: typeof arguments[1] === 'string' ? arguments[1] : null,
        });
        return original.apply(fs, arguments);
      };
    });

    // Sync variants
    var syncOps = ['readFileSync', 'writeFileSync', 'openSync', 'statSync', 'accessSync'];
    syncOps.forEach(function (op) {
      if (typeof fs[op] !== 'function') return;
      var original = fs[op];
      var baseOp = op.replace('Sync', '');
      fs[op] = function () {
        var filePath = typeof arguments[0] === 'string' ? arguments[0] : String(arguments[0] || '');
        emit('file_' + (baseOp === 'readFile' ? 'read' : baseOp === 'writeFile' ? 'write' : baseOp), {
          path: filePath,
          operation: baseOp,
          flags: typeof arguments[1] === 'string' ? arguments[1] : null,
        });
        return original.apply(fs, arguments);
      };
    });

    // Streams
    ['createReadStream', 'createWriteStream'].forEach(function (fn) {
      if (typeof fs[fn] !== 'function') return;
      var original = fs[fn];
      var action = fn === 'createReadStream' ? 'read' : 'write';
      fs[fn] = function () {
        var filePath = typeof arguments[0] === 'string' ? arguments[0] : String(arguments[0] || '');
        emit('file_' + action, {
          path: filePath,
          operation: fn,
        });
        return original.apply(fs, arguments);
      };
    });
  } catch (_) {
    // fs may not be available
  }
}

// ---------------------------------------------------------------------------
// 3. http / https / fetch hooks
// ---------------------------------------------------------------------------

function hookHttp() {
  try {
    ['http', 'https'].forEach(function (mod) {
      try {
        var m = require(mod);
        if (typeof m.request !== 'function') return;
        var originalRequest = m.request;
        m.request = function () {
          var options = arguments[0];
          var url = '';
          var method = 'GET';
          var headerKeys = [];
          if (typeof options === 'string') {
            url = options;
          } else if (options && typeof options === 'object') {
            url = options.href || options.url || ((options.protocol || mod + ':') + '//' + (options.hostname || options.host || 'localhost') + (options.path || '/'));
            method = (options.method || 'GET').toUpperCase();
            headerKeys = safeHeaderKeys(options.headers);
          }
          emit('socket_connect', {
            api: mod + '.request',
            method: method,
            url: url,
            host: (options && typeof options === 'object') ? (options.hostname || options.host || '') : '',
            remotePort: (options && typeof options === 'object') ? options.port : null,
            headerKeys: headerKeys,
          });
          return originalRequest.apply(m, arguments);
        };
      } catch (_) { }
    });
  } catch (_) { }

  // globalThis.fetch
  try {
    if (typeof globalThis !== 'undefined' && typeof globalThis.fetch === 'function') {
      var originalFetch = globalThis.fetch;
      globalThis.fetch = function () {
        var input = arguments[0];
        var init = arguments[1] || {};
        var url = typeof input === 'string' ? input : (input && input.url ? input.url : String(input));
        var method = (init.method || 'GET').toUpperCase();
        var bodyPreview = init.body ? truncate(init.body, 2048) : '';
        emit('socket_connect', {
          api: 'globalThis.fetch',
          method: method,
          url: url,
          headerKeys: safeHeaderKeys(init.headers),
          body_preview: bodyPreview,
        });
        return originalFetch.apply(globalThis, arguments);
      };
    }
  } catch (_) { }
}

// ---------------------------------------------------------------------------
// Install all hooks
// ---------------------------------------------------------------------------

hookChildProcess();
hookFs();
hookHttp();

emit('frida_ready', {
  message: 'node_trace.js hooks installed',
  platform: typeof Process !== 'undefined' ? Process.platform : 'unknown',
});
