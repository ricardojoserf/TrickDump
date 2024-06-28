# TrickDump - "python-flavour" branch

This branch implements the same functionality as the main branch but using Python3. You can run the files as scripts:

```
python lock.py
python shock.py
python barrel.py
```

![img1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/trickdump_py1.png)


As an alternative, you can compile the scripts to single binaries using pyinstaller with the "-F" flag:

 ```
pyinstaller -F lock.py
pyinstaller -F shock.py
pyinstaller -F barrel.py
```

![img3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/trickdump_py3.png)


Then use the *create_dump.py* script to generate the Minidump file in the attack system:

```
python3 create_dump.py -m MEMORY_FILES [-l LOCK_FILE] [-s SHOCK_FILE] [-b BARREL_FILE] [-o OUTPUT_FILE] 
```

![img2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/trickdump_py2.png)
