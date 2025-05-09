# TrickDump - Rust flavour

You can run the programs separately and get 3 JSON files and 1 ZIP file:

```
lock.exe [-j JSON_NAME] [-r]
```

```
shock.exe [-j JSON_NAME] [-r]
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

Finally, create the Minidump file using *create_dump.py*:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE] 
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_rust3.png)

<br>

-------------------------

## Trick (All in one)

If you prefer to execute only one binary, Trick generates a ZIP file containing the 3 JSON files and the ZIP file with the memory regions:

```
trick.exe [-z ZIPNAME] [-r]
```

The optional parameters are the same:

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_rust4.png)

With a ZIP file like this, unzip it and create the Minidump file using *create_dump.py* later:

![img5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_rust5.png)


<br>

-------------------------

## Compilation

Generate the binaries in Windows (generated in the folder "target/release") with:

```
cargo build --release
```


In Linux, install the compiler, Rust and the necessary libraries:

```
sudo apt install mingw-w64-x86-64-dev
curl https://sh.rustup.rs -sSf | sh
source $HOME/.cargo/env
rustup target add x86_64-pc-windows-gnu
```

Finally, cross-compile the binaries (generated in the folder "target/x86_64-pc-windows-gnu/release") with:

```
cargo build --release --target x86_64-pc-windows-gnu
```
<br>

----------------

## NativeDump

For an alternative approach that creates a Minidump file directly, check out [NativeDump](https://github.com/ricardojoserf/NativeDump).
