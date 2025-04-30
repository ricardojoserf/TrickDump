# TrickDump - Nim flavour

You can compile and run each binary using:

```
nim c -r --cpu:amd64 --opt:size --d:release lock.nim
```

```
nim c -r --cpu:amd64 --opt:size --d:release shock.nim
```

```
nim c -r --cpu:amd64 --opt:size --d:release barrel.nim
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_nim1.png)

Or simply compile the programs without the *-r* flag:

```
nim c --cpu:amd64 --opt:size --d:release lock.nim
```

```
nim c --cpu:amd64 --opt:size --d:release shock.nim
```

```
nim c --cpu:amd64 --opt:size --d:release barrel.nim
```

Finally, create the Minidump file using the *create_dump.py* in this branch. It extracts the ZIP file content to a temporary folder, necessary only for the Nim flavour:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE] 
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/refs/heads/master/images/trickdump/Screenshot_nim2.png)
