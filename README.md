# TrickDump - "peb-unreadable" branch

Testing how to create Minidump file when PEB structure is unreadable (in development):

- **Lock**: Get OS information using RtlGetVersion, like before **- No admin privilege needed!**

- **Shock**: Load *lsarv.dll* with LoadLibrary in your process and get its address and size with NtQueryVirtualMemory (it will be the same address in the lsass process!) **- No admin privilege needed!**

- **Barrel**:  Get SeDebugPrivilege privilege with NtOpenProcessToken and NtAdjustPrivilegeToken, open a handle with NtOpenProcess and get information and dump memory regions using NtQueryVirtualMemory and NtReadVirtualMemory  **- Admin privilege needed.**

-------------------------

## Usage

Execute each binary:

```
Lock.exe
```

```
Shock.exe
```

```
Barrel.exe
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_1.png)

Create Minidump file:

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_3.png)
