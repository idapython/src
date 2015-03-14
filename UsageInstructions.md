# Usage Instructions #

## Runtime Hotkeys ##
When IDA Pro is running the IDAPython plugin responds to the following hotkeys:

| **Key**    | Function  |
|:-----------|:----------|
| Alt-F7 | Run script |
| Ctrl-F3 | Execute Python statement(s) |
| Alt-F9 | Run previously executed script again |

## Batch mode execution ##

Running scripts in batch mode for automated processing is done by starting IDA Pro with the following command line options:

```
 -A -OIDAPython:yourscript.py file_to_work_on.bin
```
or
```
-Syourscript.py
```
or
```
-S"yourscript.py arg1 arg2 arg3"
```

Also check http://www.hexblog.com/?p=128