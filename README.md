# TrickDump - Nim flavour

You can run the programs separately and get 3 JSON files and 1 ZIP file:

```
lock.exe  [-j:JSON_NAME ] [-r]
```

```
shock.exe [-j:JSON_NAME ] [-r]
```

```
barrel.exe [-j:JSON_NAME ] [-z:ZIP_NAME] [-r]
```

The optional parameters are:

- **-j**: JSON file name

- **-z**: ZIP file name

- **-r**: Remap the ntdll.dll library

<br>

By default the programs do not remap the ntdll.dll library and create the files with the default names:

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_nim1.png)

It is possible to remap the ntdll.dll library using the parameter *-r* and change the default file names with *-j* and *-z*:

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_nim2.png)

Finally, create the Minidump file using the *create_dump.py* file in this branch. It extracts the ZIP file content to a temporary folder, necessary only for the Nim flavour:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE] 
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_nim3.png)

-------------------------

## Trick (All in one)

If you prefer to execute only one binary, Trick generates a ZIP file containing the 3 JSON files and the ZIP file with the memory regions:

```
trick.exe [-z:ZIPNAME] [-r]
```

The optional parameters are the same:

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_nim4.png)

With a ZIP file like this, unzip it and create the Minidump file using *create_dump.py* later:

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_nim5.png)

-------------------------

## Compilation

In Windows, install the necessary libraries and compile the binaries with:

```
nimble install winim zippy
nim c --cpu:amd64 --opt:size --d:release lock.nim
nim c --cpu:amd64 --opt:size --d:release shock.nim
nim c --cpu:amd64 --opt:size --d:release barrel.nim
nim c --cpu:amd64 --opt:size --d:release trick.nim
```

In Linux, install the compiler, nim and the necessary libraries:

```
sudo apt install mingw-w64
curl https://nim-lang.org/choosenim/init.sh -sSf | sh
source ~/.profile
export PATH=$HOME/.nimble/bin:$PATH
nimble install winim zippy
```

Finally, cross-compile the binaries:

```
nim c --cpu:amd64 --opt:size --d:release --os:windows --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc lock.nim
nim c --cpu:amd64 --opt:size --d:release --os:windows --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc shock.nim
nim c --cpu:amd64 --opt:size --d:release --os:windows --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc barrel.nim
nim c --cpu:amd64 --opt:size --d:release --os:windows --gcc.exe:x86_64-w64-mingw32-gcc --gcc.linkerexe:x86_64-w64-mingw32-gcc trick.nim
```
