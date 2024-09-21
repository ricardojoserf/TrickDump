# Trickdump - "bof-flavour" branch

This branch implements the same functionality as the main branch but using BOFs (Beacon Object Files).

You can execute the files using TrustedSec's [COFFLoader](https://github.com/trustedsec/COFFLoader):

```
COFFLoader64.exe go lock_bof.o
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF1.png)

```
COFFLoader64.exe go shock_bof.o
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF2.png)

```
COFFLoader64.exe go barrel_bof.o
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF3.png)


I could not create a ZIP file in a BOF file so the memory region dumps are created in a directory with a random name.

Use the updated *create_dump.py* script to generate the Minidump file in your attack system using the *-d* parameter for the directory path:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-d BARREL_DIRECTORY] [-o OUTPUT_FILE]
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF4.png)

-------------------------

## All in one

If you prefer to execute only one file, Trick BOF generates the 3 JSON files and the directory with the memory regions:

```
COFFLoader64.exe go trick_bof.o
```

It creates all the files, which you can use to create the Minidump file using *create_dump.py*:

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF5.png)
