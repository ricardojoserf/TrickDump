# TrickDump

TrickDump allows to dump the lsass process without generating a Minidump file. The attack is executed in three steps and these programs generate JSON and memory dump file(s): 

- **Lock**: Get OS information using RtlGetVersion.

- **Shock**: Get SeDebugPrivilege with NtOpenProcessToken and NtAdjustPrivilegeToken, open a handle with NtOpenProcess and then get modules information using NtQueryInformationProcess and NtReadVirtualMemory.

- **Barrel**: Get SeDebugPrivilege, open a handle and then get information and dump memory regions using NtQueryVirtualMemory and NtReadVirtualMemory.

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/trickdump.drawio.png)


Then use the *create_dump.py* script to generate the Minidump file in the attack system:

```
python3 create_dump.py -m MEMORY_FILES [-l LOCK_FILE] [-s SHOCK_FILE] [-b BARREL_FILE] [-o OUTPUT_FILE] 
```

The benefits of this technique are:

- There is never a valid Minidump file in disk, memory or the network traffic.

- There is not a single program or process executing the whole attack but three separate ones, which may raise less flags.

- The programs only use NTAPIS (this project is a variant of [NativeDump](https://github.com/ricardojoserf/NativeDump)).

- Each program allows to overwrite the ntdll.dll library ".text" section to bypass API hooking:
  - "disk": Using a DLL already on disk. If a second argument is not used the path is "C:\Windows\System32\ntdll.dll".
  - "knowndlls": Using the KnownDlls folder.
  - "debugproc": Using a process created in debug mode. If a second argument is not used the process is "c:\windows\system32\calc.exe".
  - "download": Using a URL to download the file.

-------------------------

## Example

The programs are executed in the victim system which create the three JSON files. In this case ntdll.dll is not overwritten and the Barrel.exe program has the "big_file" boolean value set to True, so the program creates only one file with all the dumped memory regions:

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_1.png)

After exfiltrating the files, the Minidump file is generated:

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_2.png)

Now the programs are executed with a different ntdll.dll overwrite technique each. The Barrel.exe program has the "big_file" boolean value set to False, so the program creates a directory and one dump file per memory region inside:

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_3.png)

The Minidump file is generated using the only mandatory argument, *-m*, which indicates the path to the memory file or the directory with all region dumps:

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_4.png)
