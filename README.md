# TrickDump - Nim flavour

Compile all the binaries with:

```
nim c --cpu:amd64 --opt:size --d:release lock.nim
nim c --cpu:amd64 --opt:size --d:release shock.nim
nim c --cpu:amd64 --opt:size --d:release barrel.nim
nim c --cpu:amd64 --opt:size --d:release trick.nim
```

You can run the programs separately and get 3 JSON files and 1 ZIP file:

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

Finally, create the Minidump file using the *create_dump.py* file in this branch. It extracts the ZIP file content to a temporary folder, necessary only for the Nim flavour:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE] 
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_nim3.png)

-------------------------

## Trick: All in one

If you prefer to execute only one binary, Trick generates a ZIP file containing the 3 JSON files and the ZIP file with the memory regions:

```
trick.exe [-z ZIPNAME] [-r]
```


It creates the ZIP file locally, optionally using a ntdll.dll overwrite method:

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_nim4.png)


With a ZIP file like this, you can unzip it and create the Minidump file using *create_dump.py* later:

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_nim5.png)

<br>

Once you have the Minidump file, get the credentials using Mimikatz. Good luck! :)
