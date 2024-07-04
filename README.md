# TrickDump - "python-flavour" branch

This branch implements the same functionality as the main branch but using Python3. You can run the files as scripts:

```
python lock.py [-o OPTION] [-p PATH]
```
```
python shock.py [-o OPTION] [-p PATH]
```
```
python barrel.py [-o OPTION] [-p PATH]
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/trickdump_py1.png)

You can use the *-o* parameter for overwriting the ntdll.dll library:
- "disk": Using a DLL already on disk. If *-p* parameter is not used the path is "C:\Windows\System32\ntdll.dll".
- "knowndlls": Using the KnownDlls folder.
- "debugproc": Using a process created in debug mode. If *-p* parameter is not used the process is "c:\windows\system32\calc.exe".

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/trickdump_py4.png)

As an alternative, you can compile the scripts to single binaries using pyinstaller with the "-F" flag:

```
pyinstaller -F lock.py
```
```
pyinstaller -F shock.py
```
```
pyinstaller -F barrel.py
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/trickdump_py3.png)


Then use the *create_dump.py* script to generate the Minidump file in the attack system:

```
python3 create_dump.py -m MEMORY_FILES [-l LOCK_FILE] [-s SHOCK_FILE] [-b BARREL_FILE] [-o OUTPUT_FILE] 
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/trickdump_py2.png)
