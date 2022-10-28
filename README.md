# ErebusGate

---

A quick example of the Erebus Gate technique in Nim

## Usage

Just compile the code 

```
nim c -d=mingw --app=console --cpu=amd64 .\ErebusGate.nim
```

## Demonstration

Check the the first byte and the third byte is 0xe9 to check whether they is hooked。

```
            # Classic hook API 
            # Check the the first byte is 0xe9
            elif cast[PBYTE](cast[ByteAddress](pFuncAddr))[] == 0xE9:
                for idx in countup(1,500):
                    if cast[PBYTE](cast[ByteAddress](pFuncAddr) + 3 + idx * UP)[] == 0xB8:
                        tableEntry.wSysCall = cast[PWORD](cast[ByteAddress](pFuncAddr) + 4 + (idx * UP))[] + cast[WORD](idx)
                        return true
                    if cast[PBYTE](cast[ByteAddress](pFuncAddr) + 3 + idx * DOWN)[] == 0xB8:
                        tableEntry.wSysCall = cast[PWORD](cast[ByteAddress](pFuncAddr) + 4 + (idx * DOWN))[] - cast[WORD](idx)
                        return true 
            # Tartarus gate from Nim
            # Check the the first three is 0xe9
            elif cast[PBYTE](cast[ByteAddress](pFuncAddr) + 3 )[] == 0xE9:
                for idx in countup(1,500):
                    if cast[PBYTE](cast[ByteAddress](pFuncAddr) + 3 + idx * UP)[] == 0xB8:
                        tableEntry.wSysCall = cast[PWORD](cast[ByteAddress](pFuncAddr) + 4 + (idx * UP))[] + cast[WORD](idx)
                        return true
                    if cast[PBYTE](cast[ByteAddress](pFuncAddr) + 3 + idx * DOWN)[] == 0xB8:
                        tableEntry.wSysCall = cast[PWORD](cast[ByteAddress](pFuncAddr) + 4 + (idx * DOWN))[] - cast[WORD](idx)
                        return true  
```

Perform "obfuscation" syscall on ASM commands。

```
asm """
        nop
        mov r10, rcx
        nop
        mov eax, `syscall`
        nop
        syscall
        ret
    """
```

![img](https://github.com/Haunted-Banshee/ErebusGate/blob/main/img.png)

