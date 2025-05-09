# TrickDump - Crystal port

This branch implements the same functionality as the main branch using the Crystal programming language. You can run the programs separately and get 3 JSON files and 1 ZIP file:

```
lock.exe [-j JSON_NAME] [-r]
```
```
shock.exe [-j JSON_NAME] [-r]
```
```
barrel.exe [-j JSON_NAME] [-z ZIP_NAME] [-r]
```

The optional parameters are:

- **-j**: JSON file name

- **-z**: ZIP file name

- **-r**: Remap the ntdll.dll library

<br>

By default the programs do not remap the ntdll.dll library and create the files with the default names:

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/crystal_trick1.png)


It is possible to remap the ntdll.dll library using the parameter *-r* and change the default file names with *-j* and *-z*:

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/crystal_trick2.png)


Then use the *create_dump.py* script to generate the Minidump file in the attack system:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE]
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/crystal_trick3.png)

<br>

-------------------------

## Trick (All in one)

If you prefer to execute only one binary, Trick.exe generates a ZIP file containing the 3 JSON files and the ZIP file with the memory regions:

```
trick.exe [-z ZIPNAME] [-r]
```

It creates the ZIP file locally, optionally using a ntdll.dll overwrite method:

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/crystal_trick4.png)


With a ZIP file like this, you can unzip it and create the Minidump file using *create_dump.py* later:

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/crystal_trick5.png)

<br>

-------------------------

## Build

First resolve and install dependencies ([crystal-garage/crystal-zip64](https://github.com/crystal-garage/crystal-zip64) is the only one):

```
shards install
```

Then build the binaries you need:

```
crystal build lock.cr --release
```
```
crystal build shock.cr --release
```
```
crystal build barrel.cr --release
```
```
crystal build trick.cr --release
```

<br>

----------------

## NativeDump

For an alternative approach that creates a Minidump file directly, check out [NativeDump](https://github.com/ricardojoserf/NativeDump).

If you like Crystal, check the [crystal-flavour](https://github.com/ricardojoserf/NativeDump/tree/crystal-flavour) branch!

<br>


------------------

## References

- [Crystal Malware](https://rastamouse.me/crystal-malware/) by [Rastamouse](https://twitter.com/_rastamouse)

<br>
