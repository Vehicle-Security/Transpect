const HOOK_CONFIG = __HOOK_CONFIG__;

const O_ACCMODE = 0x3;
const O_RDONLY = 0x0;
const O_WRONLY = 0x1;
const O_RDWR = 0x2;
const O_CREAT = 0x40;
const O_TRUNC = 0x200;
const O_APPEND = 0x400;
const EACCES = 13;
const AF_INET = 2;
const AF_INET6 = 10;

const ownPid = Process.id;
const ownRole = HOOK_CONFIG.role || "parent";
const parentPid = typeof HOOK_CONFIG.parentPid === "number" ? HOOK_CONFIG.parentPid : null;
const maxChunkBytes = Math.max(1, Number(HOOK_CONFIG.maxChunkBytes || 16384));
const blockMode = HOOK_CONFIG.mode === "block";
const enableFilesystemHooks = Boolean(HOOK_CONFIG.enableFilesystemHooks);
const enableNetworkHooks = Boolean(HOOK_CONFIG.enableNetworkHooks);
const targetPath = typeof HOOK_CONFIG.targetPath === "string" ? HOOK_CONFIG.targetPath : null;
const targetArgv = Array.isArray(HOOK_CONFIG.targetArgv) ? HOOK_CONFIG.targetArgv.map((item) => String(item)) : [];
const isOpenClawGatewayBootstrap =
  targetPath === "/usr/bin/node" &&
  targetArgv.some((item) => item.includes("/usr/lib/node_modules/openclaw/openclaw.mjs")) &&
  targetArgv.includes("gateway");
const effectiveFilesystemHooks = enableFilesystemHooks && !isOpenClawGatewayBootstrap;
const effectiveNetworkHooks = enableNetworkHooks && !isOpenClawGatewayBootstrap;
const fdAliasMap = new Map([
  [1, 1],
  [2, 2],
]);
const socketFamilyMap = new Map();
const installedAttachHooks = new Set();
const installedReplaceHooks = new Set();
const policy = compilePolicy(HOOK_CONFIG.policy || {});
const errnoSetter = buildErrnoSetter();

emit({
  phase: "script_loaded",
  resource: "meta",
  op: "load",
  parent_pid: parentPid,
  child_pid: ownRole === "child" ? ownPid : null,
  detail: `role=${ownRole}`,
});

if (ownRole === "parent") {
  hookUvSpawn();
} else {
  hookExecFamily();
  hookFdAliasFamily();
  hookWriteFamily();
  if (effectiveFilesystemHooks) hookFileFamily();
  if (effectiveNetworkHooks) hookNetworkFamily();
  hookExitFamily();
}

function buildErrnoSetter() {
  const errnoLocationPtr = findExport("__errno_location");
  if (!errnoLocationPtr) return null;
  const errnoLocation = new NativeFunction(errnoLocationPtr, "pointer", []);
  return function setErrno(value) {
    try {
      errnoLocation().writeS32(value);
    } catch (_error) {
      // Best effort only.
    }
  };
}

function compilePolicy(rawPolicy) {
  return {
    exec: compileExecRules(rawPolicy.exec),
    filesystem: compileFilesystemRules(rawPolicy.filesystem),
    network: compileNetworkRules(rawPolicy.network),
  };
}

function compileExecRules(entries) {
  if (!Array.isArray(entries)) return [];
  return entries
    .map((entry) => {
      if (!entry || typeof entry !== "object") return null;
      return {
        id: String(entry.id || ""),
        exeRegex: compileRegex(entry.exeRegex, `exec:${entry.id}:exeRegex`),
        argvRegex: compileRegex(entry.argvRegex, `exec:${entry.id}:argvRegex`),
      };
    })
    .filter((entry) => entry && entry.id);
}

function compileFilesystemRules(entries) {
  if (!Array.isArray(entries)) return [];
  return entries
    .map((entry) => {
      if (!entry || typeof entry !== "object") return null;
      return {
        id: String(entry.id || ""),
        pathRegex: compileRegex(entry.pathRegex, `filesystem:${entry.id}:pathRegex`),
        ops: normalizeRuleOps(entry.ops),
      };
    })
    .filter((entry) => entry && entry.id);
}

function compileNetworkRules(entries) {
  if (!Array.isArray(entries)) return [];
  return entries
    .map((entry) => {
      if (!entry || typeof entry !== "object") return null;
      return {
        id: String(entry.id || ""),
        addressRegex: compileRegex(entry.addressRegex, `network:${entry.id}:addressRegex`),
        ops: normalizeRuleOps(entry.ops),
        ports: normalizePorts(entry.ports),
      };
    })
    .filter((entry) => entry && entry.id);
}

function normalizeRuleOps(value) {
  if (value === undefined || value === null) return [];
  if (Array.isArray(value)) return value.map((item) => String(item));
  return [String(value)];
}

function normalizePorts(value) {
  if (value === undefined || value === null) return [];
  const items = Array.isArray(value) ? value : [value];
  const ports = [];
  for (const item of items) {
    const port = Number(item);
    if (Number.isInteger(port) && port >= 0 && port <= 65535) ports.push(port);
  }
  return ports;
}

function compileRegex(pattern, label) {
  if (!pattern) return null;
  try {
    return new RegExp(pattern);
  } catch (error) {
    emit({
      phase: "regex_error",
      resource: "meta",
      op: "regex_error",
      parent_pid: parentPid,
      child_pid: ownRole === "child" ? ownPid : null,
      detail: `${label}: ${String(error)}`,
    });
    return null;
  }
}

function resetRegex(regex) {
  if (regex) regex.lastIndex = 0;
}

function emit(record, data) {
  const payload = {
    ts: new Date().toISOString(),
    parent_pid: record.parent_pid !== undefined ? record.parent_pid : parentPid,
    child_pid: record.child_pid !== undefined ? record.child_pid : ownRole === "child" ? ownPid : null,
    phase: record.phase || null,
    exe: record.exe !== undefined ? record.exe : null,
    argv: record.argv !== undefined ? record.argv : null,
    fd: record.fd !== undefined ? record.fd : null,
    chunk: record.chunk !== undefined ? record.chunk : null,
    blocked: record.blocked !== undefined ? record.blocked : null,
    errno: record.errno !== undefined ? record.errno : null,
    exit_code: record.exit_code !== undefined ? record.exit_code : null,
    resource: record.resource !== undefined ? record.resource : null,
    op: record.op !== undefined ? record.op : null,
    path: record.path !== undefined ? record.path : null,
    path2: record.path2 !== undefined ? record.path2 : null,
    family: record.family !== undefined ? record.family : null,
    address: record.address !== undefined ? record.address : null,
    port: record.port !== undefined ? record.port : null,
    rule_id: record.rule_id !== undefined ? record.rule_id : null,
  };

  for (const [key, value] of Object.entries(record)) {
    if (!(key in payload)) payload[key] = value;
  }

  if (data !== undefined) {
    send(payload, data);
  } else {
    send(payload);
  }
}

function hookUvSpawn() {
  const uvSpawnPtr = findExport("uv_spawn");
  if (!uvSpawnPtr) {
    emit({
      phase: "hook_missing",
      resource: "process",
      op: "spawn",
      detail: "uv_spawn not found",
    });
    return;
  }

  const original = new NativeFunction(uvSpawnPtr, "int", ["pointer", "pointer", "pointer"]);

  Interceptor.replace(
    uvSpawnPtr,
    new NativeCallback(function (loop, handle, optionsPtr) {
      const details = readUvSpawnOptions(optionsPtr);
      const rule = findMatchingExecRule(details.exe, details.argv);
      const blocked = blockMode && rule !== null;
      emit({
        phase: "spawn_intent",
        resource: "process",
        op: "spawn",
        exe: details.exe,
        argv: details.argv,
        blocked,
        errno: blocked ? 126 : null,
        rule_id: rule ? rule.id : null,
      });

      if (blocked) {
        overwriteUvSpawnCommand(optionsPtr, "/bin/sh", ["/bin/sh", "-lc", "exit 126"]);
        emit({
          phase: "spawn_blocked",
          resource: "process",
          op: "spawn",
          exe: details.exe,
          argv: details.argv,
          blocked: true,
          errno: 126,
          rule_id: rule.id,
          block_strategy: "uv_spawn_command_rewrite",
        });
      }

      const result = original(loop, handle, optionsPtr);
      if (result !== 0) {
        emit({
          phase: "spawn_result",
          resource: "process",
          op: "spawn",
          exe: details.exe,
          argv: details.argv,
          blocked,
          errno: Math.abs(result),
          uv_result: result,
          rule_id: rule ? rule.id : null,
        });
      }
      return result;
    }, "int", ["pointer", "pointer", "pointer"]),
  );
}

function hookExecFamily() {
  hookExecLike("execve", "int", ["pointer", "pointer", "pointer"], (args) => ({
    exe: readUtf8Safe(args[0]),
    argv: readArgv(args[1]),
  }));

  hookExecLike("execvp", "int", ["pointer", "pointer"], (args) => ({
    exe: readUtf8Safe(args[0]),
    argv: readArgv(args[1]),
  }));
}

function hookExecLike(name, retType, argTypes, extractor) {
  const ptr = findExport(name);
  if (!ptr) {
    emit({
      phase: "hook_missing",
      resource: "process",
      op: "exec",
      detail: `${name} not found`,
    });
    return;
  }
  if (!markHookInstalled(installedReplaceHooks, ptr)) return;

  const original = new NativeFunction(ptr, retType, argTypes);

  Interceptor.replace(
    ptr,
    new NativeCallback(function () {
      const args = Array.prototype.slice.call(arguments);
      const details = extractor(args);
      const rule = findMatchingExecRule(details.exe, details.argv);
      const blocked = blockMode && rule !== null;

      emit({
        phase: "exec_call",
        resource: "process",
        op: "exec",
        exe: details.exe,
        argv: details.argv,
        blocked,
        errno: blocked ? EACCES : null,
        api: name,
        rule_id: rule ? rule.id : null,
      });

      if (blocked) {
        if (errnoSetter) errnoSetter(EACCES);
        emit({
          phase: "exec_blocked",
          resource: "process",
          op: "exec",
          exe: details.exe,
          argv: details.argv,
          blocked: true,
          errno: EACCES,
          api: name,
          rule_id: rule.id,
          block_strategy: "exec_errno",
        });
        return -1;
      }

      return original.apply(null, args);
    }, retType, argTypes),
  );
}

function hookWriteFamily() {
  const writePtr = findExport("write");
  if (writePtr && markHookInstalled(installedAttachHooks, writePtr)) {
    Interceptor.attach(writePtr, {
      onEnter(args) {
        const rawFd = args[0].toInt32();
        const fd = resolveLogicalFd(rawFd);
        if (fd !== 1 && fd !== 2) return;
        const size = numberFromNative(args[2]);
        if (size <= 0) return;
        const chunk = readByteArraySafe(args[1], size, maxChunkBytes);
        if (chunk !== null) {
          emit(
            {
              phase: fd === 1 ? "stdout" : "stderr",
              resource: "process",
              op: fd === 1 ? "stdout" : "stderr",
              fd,
              raw_fd: rawFd,
            },
            chunk,
          );
        }
      },
    });
  }

  const writevPtr = findExport("writev");
  if (writevPtr && markHookInstalled(installedAttachHooks, writevPtr)) {
    Interceptor.attach(writevPtr, {
      onEnter(args) {
        const rawFd = args[0].toInt32();
        const fd = resolveLogicalFd(rawFd);
        if (fd !== 1 && fd !== 2) return;
        const iov = args[1];
        const iovCount = args[2].toInt32();
        const entries = readIovecEntries(iov, iovCount, maxChunkBytes);
        for (const entry of entries) {
          emit(
            {
              phase: fd === 1 ? "stdout" : "stderr",
              resource: "process",
              op: fd === 1 ? "stdout" : "stderr",
              fd,
              raw_fd: rawFd,
            },
            entry,
          );
        }
      },
    });
  }
}

function hookFdAliasFamily() {
  hookDupLike("dup2", 0, 1);
  hookDupLike("dup3", 0, 1);

  const closePtr = findExport("close");
  if (closePtr && markHookInstalled(installedAttachHooks, closePtr)) {
    Interceptor.attach(closePtr, {
      onEnter(args) {
        const fd = args[0].toInt32();
        fdAliasMap.delete(fd);
        socketFamilyMap.delete(fd);
      },
    });
  }
}

function hookDupLike(name, oldFdIndex, newFdIndex) {
  const ptr = findExport(name);
  if (!ptr) return;
  if (!markHookInstalled(installedAttachHooks, ptr)) return;
  Interceptor.attach(ptr, {
    onEnter(args) {
      this.oldFd = args[oldFdIndex].toInt32();
      this.newFd = args[newFdIndex].toInt32();
    },
    onLeave(retval) {
      if (retval.toInt32() === -1) return;
      fdAliasMap.set(this.newFd, resolveLogicalFd(this.oldFd));
      if (socketFamilyMap.has(this.oldFd)) {
        socketFamilyMap.set(this.newFd, socketFamilyMap.get(this.oldFd));
      }
    },
  });
}

function hookFileFamily() {
  hookOpenLike("open", false);
  hookOpenLike("open64", false);
  hookOpenLike("openat", true);
  hookOpenLike("openat64", true);
  hookCreat();
  hookPathUnary("unlink", "file_delete", "delete");
  hookUnlinkAt();
  hookRename();
  hookRenameAt();
  hookPathUnary("mkdir", "file_mkdir", "mkdir");
  hookPathUnary("rmdir", "file_rmdir", "rmdir");
}

function hookOpenLike(name, atLike) {
  const ptr = findExport(name);
  if (!ptr) return;
  if (!markHookInstalled(installedReplaceHooks, ptr)) return;
  const argTypes = atLike ? ["int", "pointer", "int", "int"] : ["pointer", "int", "int"];
  const original = new NativeFunction(ptr, "int", argTypes);

  Interceptor.replace(
    ptr,
    new NativeCallback(function () {
      const args = Array.prototype.slice.call(arguments);
      const pathIndex = atLike ? 1 : 0;
      const flagsIndex = atLike ? 2 : 1;
      const path = readUtf8Safe(args[pathIndex]);
      const flags = Number(args[flagsIndex]) | 0;
      const action = classifyOpenFlags(flags);
      const rule = findMatchingFilesystemRule(path, null, action.op);
      const blocked = blockMode && rule !== null;
      emit({
        phase: action.phase,
        resource: "filesystem",
        op: action.op,
        path,
        blocked,
        errno: blocked ? EACCES : null,
        rule_id: rule ? rule.id : null,
        api: name,
      });
      if (blocked) {
        setErrno(EACCES);
        return -1;
      }
      return original.apply(null, args);
    }, "int", argTypes),
  );
}

function hookCreat() {
  const ptr = findExport("creat");
  if (!ptr) return;
  if (!markHookInstalled(installedReplaceHooks, ptr)) return;
  const original = new NativeFunction(ptr, "int", ["pointer", "int"]);

  Interceptor.replace(
    ptr,
    new NativeCallback(function (pathPtr, mode) {
      const path = readUtf8Safe(pathPtr);
      const rule = findMatchingFilesystemRule(path, null, "create");
      const blocked = blockMode && rule !== null;
      emit({
        phase: "file_create",
        resource: "filesystem",
        op: "create",
        path,
        blocked,
        errno: blocked ? EACCES : null,
        rule_id: rule ? rule.id : null,
        api: "creat",
      });
      if (blocked) {
        setErrno(EACCES);
        return -1;
      }
      return original(pathPtr, mode);
    }, "int", ["pointer", "int"]),
  );
}

function hookPathUnary(name, phase, op) {
  const ptr = findExport(name);
  if (!ptr) return;
  if (!markHookInstalled(installedReplaceHooks, ptr)) return;
  const unaryArgTypes = name === "mkdir" ? ["pointer", "int"] : ["pointer"];
  const unaryOriginal = new NativeFunction(ptr, "int", unaryArgTypes);

  Interceptor.replace(
    ptr,
    new NativeCallback(function () {
      const args = Array.prototype.slice.call(arguments);
      const path = readUtf8Safe(args[0]);
      const rule = findMatchingFilesystemRule(path, null, op);
      const blocked = blockMode && rule !== null;
      emit({
        phase,
        resource: "filesystem",
        op,
        path,
        blocked,
        errno: blocked ? EACCES : null,
        rule_id: rule ? rule.id : null,
        api: name,
      });
      if (blocked) {
        setErrno(EACCES);
        return -1;
      }
      return unaryOriginal.apply(null, args);
    }, "int", unaryArgTypes),
  );
}

function hookUnlinkAt() {
  const ptr = findExport("unlinkat");
  if (!ptr) return;
  if (!markHookInstalled(installedReplaceHooks, ptr)) return;
  const original = new NativeFunction(ptr, "int", ["int", "pointer", "int"]);

  Interceptor.replace(
    ptr,
    new NativeCallback(function (dirfd, pathPtr, flags) {
      const path = readUtf8Safe(pathPtr);
      const rule = findMatchingFilesystemRule(path, null, "delete");
      const blocked = blockMode && rule !== null;
      emit({
        phase: "file_delete",
        resource: "filesystem",
        op: "delete",
        path,
        blocked,
        errno: blocked ? EACCES : null,
        rule_id: rule ? rule.id : null,
        api: "unlinkat",
      });
      if (blocked) {
        setErrno(EACCES);
        return -1;
      }
      return original(dirfd, pathPtr, flags);
    }, "int", ["int", "pointer", "int"]),
  );
}

function hookRename() {
  const ptr = findExport("rename");
  if (!ptr) return;
  if (!markHookInstalled(installedReplaceHooks, ptr)) return;
  const original = new NativeFunction(ptr, "int", ["pointer", "pointer"]);

  Interceptor.replace(
    ptr,
    new NativeCallback(function (oldPathPtr, newPathPtr) {
      const oldPath = readUtf8Safe(oldPathPtr);
      const newPath = readUtf8Safe(newPathPtr);
      const rule = findMatchingFilesystemRule(oldPath, newPath, "rename");
      const blocked = blockMode && rule !== null;
      emit({
        phase: "file_rename",
        resource: "filesystem",
        op: "rename",
        path: oldPath,
        path2: newPath,
        blocked,
        errno: blocked ? EACCES : null,
        rule_id: rule ? rule.id : null,
        api: "rename",
      });
      if (blocked) {
        setErrno(EACCES);
        return -1;
      }
      return original(oldPathPtr, newPathPtr);
    }, "int", ["pointer", "pointer"]),
  );
}

function hookRenameAt() {
  const ptr = findExport("renameat");
  if (!ptr) return;
  if (!markHookInstalled(installedReplaceHooks, ptr)) return;
  const original = new NativeFunction(ptr, "int", ["int", "pointer", "int", "pointer"]);

  Interceptor.replace(
    ptr,
    new NativeCallback(function (oldDirFd, oldPathPtr, newDirFd, newPathPtr) {
      const oldPath = readUtf8Safe(oldPathPtr);
      const newPath = readUtf8Safe(newPathPtr);
      const rule = findMatchingFilesystemRule(oldPath, newPath, "rename");
      const blocked = blockMode && rule !== null;
      emit({
        phase: "file_rename",
        resource: "filesystem",
        op: "rename",
        path: oldPath,
        path2: newPath,
        blocked,
        errno: blocked ? EACCES : null,
        rule_id: rule ? rule.id : null,
        api: "renameat",
      });
      if (blocked) {
        setErrno(EACCES);
        return -1;
      }
      return original(oldDirFd, oldPathPtr, newDirFd, newPathPtr);
    }, "int", ["int", "pointer", "int", "pointer"]),
  );
}

function hookNetworkFamily() {
  hookSocket();
  hookConnect();
  hookSendTo();
  hookGetAddrInfo();
}

function hookSocket() {
  const ptr = findExport("socket");
  if (!ptr) return;
  if (!markHookInstalled(installedAttachHooks, ptr)) return;
  Interceptor.attach(ptr, {
    onEnter(args) {
      this.family = args[0].toInt32();
    },
    onLeave(retval) {
      const fd = retval.toInt32();
      if (fd >= 0) {
        socketFamilyMap.set(fd, familyLabel(this.family));
      }
    },
  });
}

function hookConnect() {
  const ptr = findExport("connect");
  if (!ptr) return;
  if (!blockMode) {
    if (!markHookInstalled(installedAttachHooks, ptr)) return;
    Interceptor.attach(ptr, {
      onEnter(args) {
        const sockFd = args[0].toInt32();
        const endpoint = parseSockAddr(args[1]);
        emit({
          phase: "net_connect",
          resource: "network",
          op: "connect",
          fd: sockFd,
          family: endpoint.family || socketFamilyMap.get(sockFd) || null,
          address: endpoint.address,
          port: endpoint.port,
          blocked: false,
          errno: null,
          rule_id: null,
          api: "connect",
        });
      },
    });
    return;
  }

  if (!markHookInstalled(installedReplaceHooks, ptr)) return;
  const original = new NativeFunction(ptr, "int", ["int", "pointer", "int"]);

  Interceptor.replace(
    ptr,
    new NativeCallback(function (sockFd, sockaddrPtr, addrLen) {
      const endpoint = parseSockAddr(sockaddrPtr);
      const rule = findMatchingNetworkRule(endpoint.address, endpoint.port, "connect");
      const blocked = rule !== null;
      emit({
        phase: "net_connect",
        resource: "network",
        op: "connect",
        fd: sockFd,
        family: endpoint.family || socketFamilyMap.get(sockFd) || null,
        address: endpoint.address,
        port: endpoint.port,
        blocked,
        errno: blocked ? EACCES : null,
        rule_id: rule ? rule.id : null,
        api: "connect",
      });
      if (blocked) {
        setErrno(EACCES);
        return -1;
      }
      return original(sockFd, sockaddrPtr, addrLen);
    }, "int", ["int", "pointer", "int"]),
  );
}

function hookSendTo() {
  const ptr = findExport("sendto");
  if (!ptr) return;
  if (!blockMode) {
    if (!markHookInstalled(installedAttachHooks, ptr)) return;
    Interceptor.attach(ptr, {
      onEnter(args) {
        const sockFd = args[0].toInt32();
        const endpoint = parseSockAddr(args[4]);
        emit({
          phase: "net_sendto",
          resource: "network",
          op: "sendto",
          fd: sockFd,
          family: endpoint.family || socketFamilyMap.get(sockFd) || null,
          address: endpoint.address,
          port: endpoint.port,
          blocked: false,
          errno: null,
          rule_id: null,
          api: "sendto",
        });
      },
    });
    return;
  }

  if (!markHookInstalled(installedReplaceHooks, ptr)) return;
  const original = new NativeFunction(ptr, "int", ["int", "pointer", "int", "int", "pointer", "int"]);

  Interceptor.replace(
    ptr,
    new NativeCallback(function (sockFd, bufPtr, len, flags, destAddrPtr, addrLen) {
      const endpoint = parseSockAddr(destAddrPtr);
      const rule = endpoint.address !== null ? findMatchingNetworkRule(endpoint.address, endpoint.port, "sendto") : null;
      const blocked = rule !== null;
      emit({
        phase: "net_sendto",
        resource: "network",
        op: "sendto",
        fd: sockFd,
        family: endpoint.family || socketFamilyMap.get(sockFd) || null,
        address: endpoint.address,
        port: endpoint.port,
        blocked,
        errno: blocked ? EACCES : null,
        rule_id: rule ? rule.id : null,
        api: "sendto",
      });
      if (blocked) {
        setErrno(EACCES);
        return -1;
      }
      return original(sockFd, bufPtr, len, flags, destAddrPtr, addrLen);
    }, "int", ["int", "pointer", "int", "int", "pointer", "int"]),
  );
}

function hookGetAddrInfo() {
  const ptr = findExport("getaddrinfo");
  if (!ptr) return;
  if (!markHookInstalled(installedAttachHooks, ptr)) return;
  Interceptor.attach(ptr, {
    onEnter(args) {
      emit({
        phase: "dns_query",
        resource: "network",
        op: "dns_query",
        address: readUtf8Safe(args[0]),
        port: parseServicePort(readUtf8Safe(args[1])),
        api: "getaddrinfo",
      });
    },
  });
}

function hookExitFamily() {
  hookExitLike("exit");
  hookExitLike("_exit");
}

function hookExitLike(name) {
  const ptr = findExport(name);
  if (!ptr) return;
  if (!markHookInstalled(installedAttachHooks, ptr)) return;
  Interceptor.attach(ptr, {
    onEnter(args) {
      emit({
        phase: "exit",
        resource: "process",
        op: "exit",
        exit_code: args[0].toInt32(),
      });
    },
  });
}

function findExport(name) {
  try {
    return Module.findGlobalExportByName(name);
  } catch (_error) {
    return null;
  }
}

function markHookInstalled(registry, ptr) {
  const key = String(ptr);
  if (registry.has(key)) return false;
  registry.add(key);
  return true;
}

function setErrno(value) {
  if (errnoSetter) errnoSetter(value);
}

function findMatchingExecRule(exe, argv) {
  const joined = Array.isArray(argv) ? argv.join(" ") : "";
  for (const rule of policy.exec) {
    if (rule.exeRegex && exe) {
      resetRegex(rule.exeRegex);
      if (rule.exeRegex.test(exe)) return rule;
    }
    if (rule.argvRegex) {
      resetRegex(rule.argvRegex);
      if (rule.argvRegex.test(joined)) return rule;
    }
  }
  return null;
}

function findMatchingFilesystemRule(path, path2, op) {
  for (const rule of policy.filesystem) {
    if (rule.ops.length > 0 && !rule.ops.includes(op)) continue;
    if (!rule.pathRegex) return rule;
    const matchesPath = path ? testRegex(rule.pathRegex, path) : false;
    const matchesPath2 = path2 ? testRegex(rule.pathRegex, path2) : false;
    if (matchesPath || matchesPath2) return rule;
  }
  return null;
}

function findMatchingNetworkRule(address, port, op) {
  for (const rule of policy.network) {
    if (rule.ops.length > 0 && !rule.ops.includes(op)) continue;
    if (rule.ports.length > 0 && !rule.ports.includes(port)) continue;
    if (!rule.addressRegex) return rule;
    if (address && testRegex(rule.addressRegex, address)) return rule;
  }
  return null;
}

function testRegex(regex, value) {
  resetRegex(regex);
  return regex.test(value);
}

function classifyOpenFlags(flags) {
  const accessMode = flags & O_ACCMODE;
  const creates = (flags & O_CREAT) !== 0;
  const writes =
    accessMode === O_WRONLY ||
    accessMode === O_RDWR ||
    (flags & O_TRUNC) !== 0 ||
    (flags & O_APPEND) !== 0 ||
    creates;

  if (creates) return { phase: "file_create", op: "create" };
  if (writes) return { phase: "file_open_write", op: "open_write" };
  if (accessMode === O_RDONLY || accessMode === O_ACCMODE) return { phase: "file_open_read", op: "open_read" };
  return { phase: "file_open_read", op: "open_read" };
}

function resolveLogicalFd(fd) {
  const seen = new Set();
  let current = fd;
  while (fdAliasMap.has(current) && !seen.has(current)) {
    seen.add(current);
    const mapped = fdAliasMap.get(current);
    if (mapped === undefined || mapped === current) break;
    current = mapped;
  }
  return current;
}

function parseSockAddr(addrPtr) {
  if (!addrPtr || addrPtr.isNull()) {
    return {
      family: null,
      address: null,
      port: null,
    };
  }
  try {
    const familyNumber = addrPtr.readU16();
    if (familyNumber === AF_INET) {
      return {
        family: "AF_INET",
        address: formatIpv4(addrPtr.add(4)),
        port: readBigEndianPort(addrPtr.add(2)),
      };
    }
    if (familyNumber === AF_INET6) {
      return {
        family: "AF_INET6",
        address: formatIpv6(addrPtr.add(8)),
        port: readBigEndianPort(addrPtr.add(2)),
      };
    }
    return {
      family: familyLabel(familyNumber),
      address: null,
      port: null,
    };
  } catch (_error) {
    return {
      family: null,
      address: null,
      port: null,
    };
  }
}

function familyLabel(familyNumber) {
  if (familyNumber === AF_INET) return "AF_INET";
  if (familyNumber === AF_INET6) return "AF_INET6";
  if (familyNumber === null || familyNumber === undefined) return null;
  return `AF_${familyNumber}`;
}

function readBigEndianPort(ptr) {
  return (ptr.readU8() << 8) | ptr.add(1).readU8();
}

function formatIpv4(ptr) {
  return [0, 1, 2, 3].map((offset) => ptr.add(offset).readU8()).join(".");
}

function formatIpv6(ptr) {
  const groups = [];
  for (let index = 0; index < 16; index += 2) {
    const high = ptr.add(index).readU8();
    const low = ptr.add(index + 1).readU8();
    groups.push(((high << 8) | low).toString(16));
  }
  return groups.join(":");
}

function parseServicePort(service) {
  if (!service) return null;
  const port = Number(service);
  if (Number.isInteger(port) && port >= 0 && port <= 65535) return port;
  return null;
}

function readArgv(argvPtr) {
  const values = [];
  if (!argvPtr || argvPtr.isNull()) return values;
  const maxArgs = 128;
  for (let index = 0; index < maxArgs; index += 1) {
    const itemPtr = argvPtr.add(index * Process.pointerSize).readPointer();
    if (itemPtr.isNull()) break;
    values.push(readUtf8Safe(itemPtr));
  }
  return values;
}

function readUvSpawnOptions(optionsPtr) {
  if (!optionsPtr || optionsPtr.isNull()) {
    return {
      exe: "uv_spawn",
      argv: [],
    };
  }
  const filePtr = optionsPtr.add(Process.pointerSize).readPointer();
  const argvPtr = optionsPtr.add(Process.pointerSize * 2).readPointer();
  return {
    exe: readUtf8Safe(filePtr),
    argv: readArgv(argvPtr),
  };
}

function overwriteUvSpawnCommand(optionsPtr, command, argv) {
  const fileSlot = optionsPtr.add(Process.pointerSize);
  const argvSlot = optionsPtr.add(Process.pointerSize * 2);
  const commandPtr = Memory.allocUtf8String(command);
  const argvPointers = argv.map((value) => Memory.allocUtf8String(value));
  const argvBlock = Memory.alloc(Process.pointerSize * (argvPointers.length + 1));

  for (let index = 0; index < argvPointers.length; index += 1) {
    argvBlock.add(index * Process.pointerSize).writePointer(argvPointers[index]);
  }
  argvBlock.add(argvPointers.length * Process.pointerSize).writePointer(ptr(0));

  fileSlot.writePointer(commandPtr);
  argvSlot.writePointer(argvBlock);
}

function readUtf8Safe(ptr) {
  if (!ptr || ptr.isNull()) return null;
  try {
    return ptr.readUtf8String();
  } catch (_error) {
    return null;
  }
}

function numberFromNative(value) {
  if (typeof value === "number") return value;
  if (value === null || value === undefined) return 0;
  if (typeof value.toNumber === "function") return value.toNumber();
  return Number(value);
}

function readByteArraySafe(ptr, size, cap) {
  if (!ptr || ptr.isNull()) return null;
  const safeSize = Math.max(0, Math.min(size, cap));
  if (safeSize === 0) return null;
  try {
    return ptr.readByteArray(safeSize);
  } catch (_error) {
    return null;
  }
}

function readIovecEntries(iovPtr, count, cap) {
  const chunks = [];
  if (!iovPtr || iovPtr.isNull() || count <= 0) return chunks;
  const stride = Process.pointerSize * 2;
  let remaining = cap;
  for (let index = 0; index < count && remaining > 0; index += 1) {
    const entryPtr = iovPtr.add(index * stride);
    const basePtr = entryPtr.readPointer();
    const lenPtr = entryPtr.add(Process.pointerSize);
    const size = Process.pointerSize === 8 ? lenPtr.readU64().toNumber() : lenPtr.readU32();
    const chunk = readByteArraySafe(basePtr, size, remaining);
    if (chunk === null) continue;
    remaining -= chunk.byteLength;
    chunks.push(chunk);
  }
  return chunks;
}
