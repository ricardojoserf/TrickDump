# TrickDump

Dump the lsass process without generating a Minidump file in the victim system in three steps: 
- **Lock**: Get OS information using RtlGetVersion.
- **Shock**: Get SeDebugPrivilege with NtOpenProcessToken and NtAdjustPrivilegeToken, open a handle with NtOpenProcess and then get modules information using NtQueryInformationProcess and NtReadVirtualMemory.
- **Barrel**: Get SeDebugPrivilege, open a handle and then get information and dump memory regions using NtQueryVirtualMemory and NtReadVirtualMemory.

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/trickdump.drawio.png)

The benefits of this technique are that there is never a valid Minidump file in disk, memory or the network traffic; there is not a single program or process executing the attack but three, which may raise less flags; and these programs only use NTAPIS, as this project is a variant of [NativeDump](https://github.com/ricardojoserf/NativeDump).

Use the *create_dump.py* script to generate the Minidump file in your attack system:

```
python3 create_dump.py -d MEMDUMPS_DIRECTORY [-l LOCK_FILE] [-s SHOCK_FILE] [-b BARREL_FILE] [-o OUTPUT_FILE] 
```

-------------------------

## Example

The programs are executed in the victim system which create the three JSON files and a directory with each memory region dump:

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_1.png)

After exfiltrating the files, the Minidump file is generated:

![img](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_2.png)

