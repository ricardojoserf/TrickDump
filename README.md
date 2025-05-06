# TrickDump - Rust flavour

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

The optional parameters are:

- **-j**: JSON file name

- **-z**: ZIP file name

- **-r**: Remap the ntdll.dll library

<br>

By default the programs do not remap the ntdll.dll library and create the files with the default names:

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_rust1.png)

It is possible to remap the ntdll.dll library using the parameter *-r* and change the default file names with *-j* and *-z*:

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_rust2.png)

Finally, create the Minidump file using the *create_dump.py* file in this branch. It extracts the ZIP file content to a temporary folder, necessary only for the Nim flavour:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE] 
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_rust3.png)

-------------------------

## Compilation

Generate the binaries in Windows with:

```
cargo build --release
```
