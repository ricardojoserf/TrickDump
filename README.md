# TrickDump - "golang-flavour" branch

This branch implements the same functionality as the main branch but using Golang. As an addition, it allows to create the zip file with a password.

You can run the files as scripts:

```
go run lock.go [-o OPTION] [-p PATH]
```
```
go run shock.go [-o OPTION] [-p PATH]
```
```
go run barrel.go [-o OPTION] [-p PATH] [-zp ZIP_PASSWORD]
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_go1.png)

You can use the *-o* parameter for overwriting the ntdll.dll library:
- "disk": Using a DLL already on disk. If *-p* parameter is not used the path is "C:\Windows\System32\ntdll.dll".
- "knowndlls": Using the KnownDlls folder.
- "debugproc": Using a process created in debug mode. If *-p* parameter is not used the process is "c:\windows\system32\calc.exe".

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_go2.png)

As an alternative, you can compile the scripts to binaries using "go build":

```
go build lock.go && go build shock.go && go build barrel.go
``` 

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_go3.png)

Then use the *create_dump.py* script to generate the Minidump file in the attack system:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-zp ZIP_PASSWORD] [-o OUTPUT_FILE]
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_go4.png)


-------------------------

## All in one

If you prefer to execute only one program, trick.go generates a ZIP file containing the 3 JSON files and the ZIP file with the memory regions:

```
go run trick.go [-o OPTION] [-p PATH]
```

You can create the ZIP file locally, optionally using a Ntdll overwrite method:

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_go5.png)

You get a ZIP file like this, unzip it and create the Minidump file with the *create_dump.py* script:

![img7](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_7.png)
