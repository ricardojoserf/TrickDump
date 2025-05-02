# TrickDump - Nim flavour

Compile binaries with:

```
nim c --cpu:amd64 --opt:size --d:release lock.nim
nim c --cpu:amd64 --opt:size --d:release shock.nim
nim c --cpu:amd64 --opt:size --d:release barrel.nim
```


```
lock.exe  [-j JSON_NAME ] [-r]
```

```
shock.exe [-j JSON_NAME ] [-r]
```

```
barrel.exe [-j JSON_NAME ] [-z ZIP_NAME] [-r]
```

Options:

- **JSON file name** (-j, optional): JSON file name

- **ZIP file name** (-z, optional): ZIP file name

- **Remap ntdll** (-r, optional): Remap the ntdll.dll library

<br>

By default the programs do not remap the ntdll.dll and create the files "lock.json", "shock.json",  "barrel.json" and "barrel.zip":

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_nim1.png)

It is possible to remap the ntdll.dll library using the parameter *-r* and change the default file names with *-j* and *-z*:

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_nim2.png)

Finally, create the Minidump file using the *create_dump.py* in this branch. It extracts the ZIP file content to a temporary folder, necessary only for the Nim flavour:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE] 
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_nim3.png)

Once you have the Minidump file, get the credentials using Mimikatz. Good luck! :)
