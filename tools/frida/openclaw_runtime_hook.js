const HOOK_CONFIG = __HOOK_CONFIG__;

const ownPid = Process.id;
const ownRole = HOOK_CONFIG.role || "parent";
const parentPid = typeof HOOK_CONFIG.parentPid === "number" ? HOOK_CONFIG.parentPid : null;
const maxChunkBytes = Math.max(1, Number(HOOK_CONFIG.maxChunkBytes || 16384));
const blockMode = HOOK_CONFIG.mode === "block";
const fdAliasMap = new Map([
  [1, 1],
  [2, 2],
]);

const exeRegex = compileRegex(HOOK_CONFIG.denyExeRegex);
const argvRegex = compileRegex(HOOK_CONFIG.denyArgvRegex);

emit({
  phase: "script_loaded",
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
  hookExitFamily();
}

function compileRegex(pattern) {
  if (!pattern) return null;
  try {
    return new RegExp(pattern);
  } catch (error) {
    emit({
      phase: "regex_error",
      parent_pid: parentPid,
      child_pid: ownRole === "child" ? ownPid : null,
      detail: String(error),
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
      detail: "uv_spawn not found",
    });
    return;
  }

  const original = new NativeFunction(uvSpawnPtr, "int", ["pointer", "pointer", "pointer"]);

  Interceptor.replace(
    uvSpawnPtr,
    new NativeCallback(function (loop, handle, optionsPtr) {
      const details = readUvSpawnOptions(optionsPtr);
      const blocked = shouldBlock(details.exe, details.argv);
      emit({
        phase: "spawn_intent",
        exe: details.exe,
        argv: details.argv,
        blocked,
        errno: blocked ? 126 : null,
      });

      if (blocked) {
        overwriteUvSpawnCommand(optionsPtr, "/bin/sh", ["/bin/sh", "-lc", "exit 126"]);
        emit({
          phase: "spawn_blocked",
          exe: details.exe,
          argv: details.argv,
          blocked: true,
          errno: 126,
          block_strategy: "uv_spawn_command_rewrite",
        });
      }

      const result = original(loop, handle, optionsPtr);
      if (result !== 0) {
        emit({
          phase: "spawn_result",
          exe: details.exe,
          argv: details.argv,
          blocked,
          errno: Math.abs(result),
          uv_result: result,
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
      detail: `${name} not found`,
    });
    return;
  }

  const original = new NativeFunction(ptr, retType, argTypes);

  Interceptor.replace(
    ptr,
    new NativeCallback(function () {
      const args = Array.prototype.slice.call(arguments);
      const details = extractor(args);

      emit({
        phase: "exec_call",
        exe: details.exe,
        argv: details.argv,
        blocked: false,
        errno: null,
        api: name,
      });

      return original.apply(null, args);
    }, retType, argTypes),
  );
}

function hookWriteFamily() {
  const writePtr = findExport("write");
  if (writePtr) {
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
  if (writevPtr) {
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
  if (closePtr) {
    Interceptor.attach(closePtr, {
      onEnter(args) {
        const fd = args[0].toInt32();
        fdAliasMap.delete(fd);
      },
    });
  }
}

function hookDupLike(name, oldFdIndex, newFdIndex) {
  const ptr = findExport(name);
  if (!ptr) return;
  Interceptor.attach(ptr, {
    onEnter(args) {
      this.oldFd = args[oldFdIndex].toInt32();
      this.newFd = args[newFdIndex].toInt32();
    },
    onLeave(retval) {
      if (retval.toInt32() === -1) return;
      fdAliasMap.set(this.newFd, resolveLogicalFd(this.oldFd));
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
  Interceptor.attach(ptr, {
    onEnter(args) {
      emit({
        phase: "exit",
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

function shouldBlock(exe, argv) {
  if (!blockMode) return false;

  if (exeRegex && exe) {
    resetRegex(exeRegex);
    if (exeRegex.test(exe)) return true;
  }

  if (argvRegex) {
    const joined = Array.isArray(argv) ? argv.join(" ") : "";
    resetRegex(argvRegex);
    if (argvRegex.test(joined)) return true;
  }

  return false;
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
