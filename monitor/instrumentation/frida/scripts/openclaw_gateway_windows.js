'use strict';

const TRACE_PATH_PREFIXES = __TRACE_PATH_PREFIXES__;
const PROCESS_INCLUDE = __PROCESS_INCLUDE__;

const HANDLE_MAP = new Map();
const SOCKET_MAP = new Map();
const HOOKED_EXPORTS = new Set();

function nowIso() {
  return new Date().toISOString();
}

function normalizePath(path) {
  return String(path || '').replace(/\//g, '\\').toLowerCase();
}

function shouldTracePath(path) {
  const normalized = normalizePath(path);
  return TRACE_PATH_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

function shouldTraceCommand(commandLine) {
  const normalized = String(commandLine || '').toLowerCase();
  return PROCESS_INCLUDE.some((token) => normalized.includes(token));
}

function safeUtf16(ptr) {
  try {
    if (!ptr || ptr.isNull()) {
      return null;
    }
    return ptr.readUtf16String();
  } catch (error) {
    return null;
  }
}

function safeU16(ptr) {
  try {
    return ptr.readU16();
  } catch (error) {
    return null;
  }
}

function summarizeBytes(ptr, length) {
  const requested = Number(length || 0);
  if (!ptr || ptr.isNull() || !requested) {
    return { length: requested, previewHex: '', previewAscii: '' };
  }
  const size = Math.min(requested, 96);
  try {
    const bytes = ptr.readByteArray(size);
    const view = new Uint8Array(bytes);
    const hex = Array.from(view).map((b) => b.toString(16).padStart(2, '0')).join('');
    const ascii = Array.from(view).map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.')).join('');
    return { length: requested, previewHex: hex, previewAscii: ascii };
  } catch (error) {
    return { length: requested, previewHex: '', previewAscii: '' };
  }
}

function emit(kind, payload) {
  send({
    type: 'trace',
    ts: nowIso(),
    pid: Process.id,
    kind,
    payload,
  });
}

function findExport(moduleName, exportName) {
  if (typeof Module.findExportByName === 'function') {
    return Module.findExportByName(moduleName, exportName);
  }
  if (typeof Module.getExportByName === 'function') {
    try {
      return Module.getExportByName(moduleName, exportName);
    } catch (error) {
      return null;
    }
  }
  return null;
}

function attachExportCandidates(moduleNames, exportName, callbacks) {
  for (const moduleName of moduleNames) {
    const address = findExport(moduleName, exportName);
    if (!address) {
      continue;
    }
    const key = `${exportName}:${address.toString()}`;
    if (HOOKED_EXPORTS.has(key)) {
      continue;
    }
    HOOKED_EXPORTS.add(key);
    Interceptor.attach(address, callbacks);
  }
}

function sockaddrToObject(addrPtr, length) {
  if (!addrPtr || addrPtr.isNull()) {
    return null;
  }
  const family = safeU16(addrPtr);
  if (family === 2 && Number(length) >= 16) {
    const portNetwork = addrPtr.add(2).readU16();
    const octets = [];
    for (let i = 0; i < 4; i += 1) {
      octets.push(addrPtr.add(4 + i).readU8());
    }
    const port = ((portNetwork & 0xff) << 8) | ((portNetwork >> 8) & 0xff);
    return {
      family: 'ipv4',
      ip: octets.join('.'),
      port,
    };
  }
  if (family === 23 && Number(length) >= 28) {
    const portNetwork = addrPtr.add(2).readU16();
    const port = ((portNetwork & 0xff) << 8) | ((portNetwork >> 8) & 0xff);
    const parts = [];
    for (let i = 0; i < 16; i += 2) {
      parts.push(addrPtr.add(8 + i).readU16().toString(16));
    }
    return {
      family: 'ipv6',
      ip: parts.join(':'),
      port,
    };
  }
  return {
    family: `af_${family}`,
    ip: null,
    port: null,
  };
}

function getSocket(handle) {
  return SOCKET_MAP.get(String(handle)) || null;
}

function rememberSocket(handle, details) {
  const key = String(handle);
  const current = SOCKET_MAP.get(key) || { firstSeenAt: nowIso(), sends: 0, recvs: 0 };
  SOCKET_MAP.set(key, Object.assign(current, details));
}

function installCreateFileW() {
  attachExportCandidates(['KernelBase.dll', 'kernel32.dll'], 'CreateFileW', {
    onEnter(args) {
      this.path = safeUtf16(args[0]);
      this.shouldEmit = shouldTracePath(this.path);
    },
    onLeave(retval) {
      if (!this.shouldEmit) {
        return;
      }
      const handle = retval.toString();
      HANDLE_MAP.set(handle, this.path);
      emit('file_open', {
        path: this.path,
        handle,
      });
    },
  });
}

function installReadFile() {
  attachExportCandidates(['KernelBase.dll', 'kernel32.dll'], 'ReadFile', {
    onEnter(args) {
      this.handle = args[0].toString();
      this.path = HANDLE_MAP.get(this.handle) || null;
      this.buffer = args[1];
      this.length = args[2].toInt32();
    },
    onLeave(retval) {
      if (!this.path) {
        return;
      }
      const success = !retval.isNull() && retval.toInt32() !== 0;
      const summary = success ? summarizeBytes(this.buffer, this.length) : { previewHex: '', previewAscii: '' };
      emit('file_read', {
        path: this.path,
        handle: this.handle,
        success,
        bytesRequested: this.length,
        previewHex: summary.previewHex,
        previewAscii: summary.previewAscii,
      });
    },
  });
}

function installWriteFile() {
  attachExportCandidates(['KernelBase.dll', 'kernel32.dll'], 'WriteFile', {
    onEnter(args) {
      this.handle = args[0].toString();
      this.path = HANDLE_MAP.get(this.handle) || null;
      this.length = args[2].toInt32();
      this.summary = summarizeBytes(args[1], this.length);
    },
    onLeave(retval) {
      if (!this.path) {
        return;
      }
      emit('file_write', {
        path: this.path,
        handle: this.handle,
        success: !retval.isNull() && retval.toInt32() !== 0,
        bytesRequested: this.length,
        previewHex: this.summary.previewHex,
        previewAscii: this.summary.previewAscii,
      });
    },
  });
}

function installCloseHandle() {
  attachExportCandidates(['KernelBase.dll', 'kernel32.dll'], 'CloseHandle', {
    onEnter(args) {
      this.handle = args[0].toString();
      this.path = HANDLE_MAP.get(this.handle) || null;
    },
    onLeave(retval) {
      if (this.path) {
        emit('file_close', {
          path: this.path,
          handle: this.handle,
          success: !retval.isNull() && retval.toInt32() !== 0,
        });
      }
      HANDLE_MAP.delete(this.handle);
    },
  });
}

function installCreateProcessW() {
  attachExportCandidates(['KernelBase.dll', 'kernel32.dll'], 'CreateProcessW', {
    onEnter(args) {
      this.applicationName = safeUtf16(args[0]);
      this.commandLine = safeUtf16(args[1]);
      this.processInformation = args[9];
      this.shouldEmit = shouldTraceCommand(this.applicationName) || shouldTraceCommand(this.commandLine);
    },
    onLeave(retval) {
      if (!this.shouldEmit) {
        return;
      }
      let childPid = null;
      if (this.processInformation && !this.processInformation.isNull()) {
        try {
          childPid = this.processInformation.add(Process.pointerSize * 2).readU32();
        } catch (error) {
          childPid = null;
        }
      }
      emit('process_spawn', {
        api: 'CreateProcessW',
        success: !retval.isNull() && retval.toInt32() !== 0,
        applicationName: this.applicationName,
        commandLine: this.commandLine,
        childPid,
      });
    },
  });
}

function installShellExecuteExW() {
  const address = findExport('shell32.dll', 'ShellExecuteExW');
  if (!address) {
    return;
  }
  Interceptor.attach(address, {
    onEnter(args) {
      this.infoPtr = args[0];
      this.file = null;
      this.parameters = null;
      this.directory = null;
      try {
        this.file = safeUtf16(this.infoPtr.add(24).readPointer());
        this.parameters = safeUtf16(this.infoPtr.add(32).readPointer());
        this.directory = safeUtf16(this.infoPtr.add(40).readPointer());
      } catch (error) {
        this.file = null;
      }
      const commandLine = [this.file, this.parameters].filter(Boolean).join(' ');
      this.shouldEmit = shouldTraceCommand(commandLine);
    },
    onLeave(retval) {
      if (!this.shouldEmit) {
        return;
      }
      emit('process_spawn', {
        api: 'ShellExecuteExW',
        success: !retval.isNull() && retval.toInt32() !== 0,
        applicationName: this.file,
        commandLine: [this.file, this.parameters].filter(Boolean).join(' '),
        cwd: this.directory,
      });
    },
  });
}

function installBind() {
  const address = findExport('ws2_32.dll', 'bind');
  if (!address) {
    return;
  }
  Interceptor.attach(address, {
    onEnter(args) {
      this.socket = args[0].toString();
      this.local = sockaddrToObject(args[1], args[2].toInt32());
    },
    onLeave(retval) {
      const success = retval.toInt32() === 0;
      if (!success) {
        return;
      }
      rememberSocket(this.socket, {
        localIp: this.local ? this.local.ip : null,
        localPort: this.local ? this.local.port : null,
        family: this.local ? this.local.family : null,
      });
      emit('socket_bind', {
        socket: this.socket,
        localIp: this.local ? this.local.ip : null,
        localPort: this.local ? this.local.port : null,
        family: this.local ? this.local.family : null,
      });
    },
  });
}

function installListen() {
  const address = findExport('ws2_32.dll', 'listen');
  if (!address) {
    return;
  }
  Interceptor.attach(address, {
    onEnter(args) {
      this.socket = args[0].toString();
      this.backlog = args[1].toInt32();
    },
    onLeave(retval) {
      const socket = getSocket(this.socket);
      if (!socket || retval.toInt32() !== 0) {
        return;
      }
      emit('socket_listen', {
        socket: this.socket,
        backlog: this.backlog,
        localIp: socket.localIp || null,
        localPort: socket.localPort || null,
        family: socket.family || null,
      });
    },
  });
}

function installAccept() {
  const address = findExport('ws2_32.dll', 'accept');
  if (!address) {
    return;
  }
  Interceptor.attach(address, {
    onEnter(args) {
      this.socket = args[0].toString();
      this.addrPtr = args[1];
      this.addrLenPtr = args[2];
    },
    onLeave(retval) {
      const acceptedSocket = retval.toString();
      if (acceptedSocket === '-1') {
        return;
      }
      let remote = null;
      try {
        const addrLen = this.addrLenPtr && !this.addrLenPtr.isNull() ? this.addrLenPtr.readS32() : 0;
        remote = sockaddrToObject(this.addrPtr, addrLen);
      } catch (error) {
        remote = null;
      }
      const parent = getSocket(this.socket);
      rememberSocket(acceptedSocket, {
        localIp: parent ? parent.localIp : null,
        localPort: parent ? parent.localPort : null,
        remoteIp: remote ? remote.ip : null,
        remotePort: remote ? remote.port : null,
        family: remote ? remote.family : (parent ? parent.family : null),
      });
      emit('socket_accept', {
        socket: acceptedSocket,
        parentSocket: this.socket,
        localIp: parent ? parent.localIp : null,
        localPort: parent ? parent.localPort : null,
        remoteIp: remote ? remote.ip : null,
        remotePort: remote ? remote.port : null,
        family: remote ? remote.family : (parent ? parent.family : null),
      });
    },
  });
}

function installConnectLike(dllName, symbolName) {
  const address = findExport(dllName, symbolName);
  if (!address) {
    return;
  }
  Interceptor.attach(address, {
    onEnter(args) {
      this.socket = args[0].toString();
      this.remote = sockaddrToObject(args[1], args[2].toInt32());
    },
    onLeave(retval) {
      const success = retval.toInt32() === 0;
      if (!success) {
        return;
      }
      rememberSocket(this.socket, {
        remoteIp: this.remote ? this.remote.ip : null,
        remotePort: this.remote ? this.remote.port : null,
        family: this.remote ? this.remote.family : null,
      });
      emit('socket_connect', {
        api: symbolName,
        socket: this.socket,
        remoteIp: this.remote ? this.remote.ip : null,
        remotePort: this.remote ? this.remote.port : null,
        family: this.remote ? this.remote.family : null,
      });
    },
  });
}

function installSend() {
  const address = findExport('ws2_32.dll', 'send');
  if (!address) {
    return;
  }
  Interceptor.attach(address, {
    onEnter(args) {
      this.socket = args[0].toString();
      this.length = args[2].toInt32();
      this.summary = summarizeBytes(args[1], this.length);
    },
    onLeave(retval) {
      const socket = getSocket(this.socket);
      if (!socket) {
        return;
      }
      socket.sends += 1;
      emit('socket_send', {
        api: 'send',
        socket: this.socket,
        remoteIp: socket.remoteIp || null,
        remotePort: socket.remotePort || null,
        sendIndex: socket.sends,
        bytesRequested: this.length,
        bytesReported: retval.toInt32(),
        previewHex: this.summary.previewHex,
        previewAscii: this.summary.previewAscii,
      });
    },
  });
}

function installWSASend() {
  const address = findExport('ws2_32.dll', 'WSASend');
  if (!address) {
    return;
  }
  Interceptor.attach(address, {
    onEnter(args) {
      this.socket = args[0].toString();
      this.bufferCount = args[2].toInt32();
      this.totalLength = 0;
      this.summary = { length: 0, previewHex: '', previewAscii: '' };
      try {
        if (this.bufferCount > 0) {
          const first = args[1];
          const len = first.readU32();
          const buf = first.add(Process.pointerSize === 8 ? 8 : 4).readPointer();
          this.totalLength = len;
          this.summary = summarizeBytes(buf, len);
          for (let i = 1; i < this.bufferCount; i += 1) {
            const entry = args[1].add(i * (Process.pointerSize === 8 ? 16 : 8));
            this.totalLength += entry.readU32();
          }
        }
      } catch (error) {
        this.totalLength = 0;
      }
    },
    onLeave(retval) {
      const socket = getSocket(this.socket);
      if (!socket) {
        return;
      }
      socket.sends += 1;
      emit('socket_send', {
        api: 'WSASend',
        socket: this.socket,
        remoteIp: socket.remoteIp || null,
        remotePort: socket.remotePort || null,
        sendIndex: socket.sends,
        bytesRequested: this.totalLength,
        success: retval.toInt32() === 0,
        previewHex: this.summary.previewHex,
        previewAscii: this.summary.previewAscii,
      });
    },
  });
}

function installRecv() {
  const address = findExport('ws2_32.dll', 'recv');
  if (!address) {
    return;
  }
  Interceptor.attach(address, {
    onEnter(args) {
      this.socket = args[0].toString();
      this.buffer = args[1];
      this.length = args[2].toInt32();
    },
    onLeave(retval) {
      const socket = getSocket(this.socket);
      const bytesRead = retval.toInt32();
      if (!socket || bytesRead <= 0) {
        return;
      }
      socket.recvs += 1;
      const summary = summarizeBytes(this.buffer, bytesRead);
      emit('socket_recv', {
        api: 'recv',
        socket: this.socket,
        remoteIp: socket.remoteIp || null,
        remotePort: socket.remotePort || null,
        recvIndex: socket.recvs,
        bytesRead,
        previewHex: summary.previewHex,
        previewAscii: summary.previewAscii,
      });
    },
  });
}

function installWSARecv() {
  const address = findExport('ws2_32.dll', 'WSARecv');
  if (!address) {
    return;
  }
  Interceptor.attach(address, {
    onEnter(args) {
      this.socket = args[0].toString();
      this.buffers = args[1];
      this.bufferCount = args[2].toInt32();
    },
    onLeave(retval) {
      const socket = getSocket(this.socket);
      if (!socket || retval.toInt32() !== 0 || this.bufferCount <= 0) {
        return;
      }
      try {
        const first = this.buffers;
        const len = first.readU32();
        const buf = first.add(Process.pointerSize === 8 ? 8 : 4).readPointer();
        socket.recvs += 1;
        const summary = summarizeBytes(buf, len);
        emit('socket_recv', {
          api: 'WSARecv',
          socket: this.socket,
          remoteIp: socket.remoteIp || null,
          remotePort: socket.remotePort || null,
          recvIndex: socket.recvs,
          bytesRead: len,
          previewHex: summary.previewHex,
          previewAscii: summary.previewAscii,
        });
      } catch (error) {
        return;
      }
    },
  });
}

function installCloseSocket() {
  const address = findExport('ws2_32.dll', 'closesocket');
  if (!address) {
    return;
  }
  Interceptor.attach(address, {
    onEnter(args) {
      this.socket = args[0].toString();
      this.socketInfo = getSocket(this.socket);
    },
    onLeave(retval) {
      if (this.socketInfo) {
        emit('socket_close', {
          socket: this.socket,
          localIp: this.socketInfo.localIp || null,
          localPort: this.socketInfo.localPort || null,
          remoteIp: this.socketInfo.remoteIp || null,
          remotePort: this.socketInfo.remotePort || null,
          success: retval.toInt32() === 0,
        });
      }
      SOCKET_MAP.delete(this.socket);
    },
  });
}

installCreateFileW();
installReadFile();
installWriteFile();
installCloseHandle();
installCreateProcessW();
installShellExecuteExW();
installBind();
installListen();
installAccept();
installConnectLike('ws2_32.dll', 'connect');
installConnectLike('ws2_32.dll', 'WSAConnect');
installSend();
installWSASend();
installRecv();
installWSARecv();
installCloseSocket();

emit('frida_ready', {
  message: 'OpenClaw gateway Windows trace hooks installed',
});
