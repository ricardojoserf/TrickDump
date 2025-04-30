# TrickDump - Nim flavour

```
nim c -r --cpu:amd64 --opt:size --d:release lock.nim
```

```
nim c -r --cpu:amd64 --opt:size --d:release shock.nim
```

```
nim c -r --cpu:amd64 --opt:size --d:release barrel.nim
```

Create the Minidump file using the custom *create_dump.py*, which first extracts the ZIP file content to a folder (for this version you need to use this script, not the one in other branches):

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE] 
```
