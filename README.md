# TrickDump

TrickDump allows to dump the lsass process without generating a Minidump file, generating instead three JSON files and one zip file with memory regions dumps. It has three steps:

- **Lock**: Get OS information using RtlGetVersion.

- **Shock**: Get SeDebugPrivilege privilege with NtOpenProcessToken and NtAdjustPrivilegeToken, open a handle with NtGetNextProcess and NtQueryInformationProcess and then get modules information using NtQueryInformationProcess and NtReadVirtualMemory.

- **Barrel**: Get SeDebugPrivilege privilege, open a handle and then get information and dump memory regions using NtQueryVirtualMemory and NtReadVirtualMemory. 


![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/trickdump.drawio.png)


Then use the *create_dump.py* script to generate the Minidump file in the attack system:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE] 
```

The benefits of this technique are:

- There is never a valid Minidump file in disk, memory or the network traffic.

- There is not a single program or process executing the whole attack but three separate ones, which may raise less flags.
  - Also if you have information about the OS of the target machine you can skip the first step ("Lock").

- The programs only use NTAPIS (this project is a variant of [NativeDump](https://github.com/ricardojoserf/NativeDump)).

- Each program allows to overwrite the ntdll.dll library ".text" section to bypass API hooking:
  - "disk": Using a DLL already on disk. If a second argument is not used the path is "C:\Windows\System32\ntdll.dll".
  - "knowndlls": Using the KnownDlls folder.
  - "debugproc": Using a process created in debug mode. If a second argument is not used the process is "c:\windows\system32\calc.exe".

It will not work if PPL is enabled, the PEB structure is unreadable or the binaries are not compiled as 64-bit.


It comes in three flavours:

- .NET: The main branch
- Python: The [python-flavour branch](https://github.com/ricardojoserf/TrickDump/tree/python-flavour)
- Golang: The [golang-flavour branch](https://github.com/ricardojoserf/TrickDump/tree/golang-flavour)

-------------------------

## Usage

The programs are executed in the victim system, creating three JSON files (with memory regions information) and one zip file (with each memory region dump).

```
Lock.exe [disk/knowndlls/debugproc]
```

```
Shock.exe [disk/knowndlls/debugproc]
```

```
Barrel.exe [disk/knowndlls/debugproc]
```

You can execute the programs directly without overwriting the ntdll.dll library:

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_1.png)

Or use one of the three different overwrite techniques:

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_2.png)

Then the Minidump file is generated:

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_3.png)
