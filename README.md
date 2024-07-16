# TrickDump

TrickDump allows to dump the lsass process without generating a Minidump file, it generates JSON files and memory dump files in 3 steps: 

- **Lock**: Get OS information using RtlGetVersion.

- **Shock**: Get process handle with NtGetNextProcess, GetProcessImageFileName and NtQueryInformationProcess, get SeDebugPrivilege privilege with NtOpenProcessToken and NtAdjustPrivilegeToken, open a handle with NtOpenProcess and then get modules information using NtQueryInformationProcess and NtReadVirtualMemory.

- **Barrel**: Get process handle, get SeDebugPrivilege privilege, open a handle and then get information and dump memory regions using NtQueryVirtualMemory and NtReadVirtualMemory. 


![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/trickdump.drawio.png)


Then use the *create_dump.py* script to generate the Minidump file in the attack system:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE] 
```

The benefits of this technique are:

- There is never a valid Minidump file in disk, memory or the network traffic.

- There is not a single program or process executing the whole attack but three separate ones, which may raise less flags.

- The programs only use NTAPIS (this project is a variant of [NativeDump](https://github.com/ricardojoserf/NativeDump)).

- Each program allows to overwrite the ntdll.dll library ".text" section to bypass API hooking:
  - "disk": Using a DLL already on disk. If a second argument is not used the path is "C:\Windows\System32\ntdll.dll".
  - "knowndlls": Using the KnownDlls folder.
  - "debugproc": Using a process created in debug mode. If a second argument is not used the process is "c:\windows\system32\calc.exe".

It comes in three flavours:

- .NET: The main branch
- Python: The [python-flavour branch](https://github.com/ricardojoserf/TrickDump/tree/python-flavour)
- Golang: The [golang-flavour branch](https://github.com/ricardojoserf/TrickDump/tree/golang-flavour)

-------------------------

## Usage

The programs are executed in the victim system and create three JSON files (with memory regions information) and one zip file (with each memory region dump).

```
Lock.exe [disk/knowndlls/debugproc]
```

```
Shock.exe [disk/knowndlls/debugproc]
```

```
Barrel.exe [disk/knowndlls/debugproc]
```

You can execute the programs directly without overwritting the ntdll.dll library:

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_1.png)

Or use one of the three different overwrite techniques:

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_3.png)

Then the Minidump file is generated:

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_4.png)