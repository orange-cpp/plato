#include "memory.h"

#include <VirtualizerSDK.h>
#include <ntddk.h>
#include <ntdef.h>
#include <ntifs.h>
#include <windef.h>

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation = 0x0B
} SYSTEM_INFORMATION_CLASS,
        *PSYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;


extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);
extern "C" NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineName);
extern "C" NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);

struct memcpy_structure
{
    void* destination;
    unsigned int max_size;
    unsigned int offset;
    unsigned char pad[0xF];
    unsigned char error_flag;
};

typedef unsigned __int64(__fastcall* PiDqSerializationWrite_t)(memcpy_structure* a1, void* a2, unsigned int a3);


typedef struct _SYSTEM_MODULE_ENTRY
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE_ENTRY, *PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;


NTSTATUS GetNtoskrnlBaseAddress(OUT PVOID* pBaseAddress)
{
    if (!pBaseAddress)
        return STATUS_INVALID_PARAMETER;


    *pBaseAddress = nullptr;

    ULONG bufferSize = 0;
    PSYSTEM_MODULE_INFORMATION pModuleInfo = nullptr;

    //
    // First call ZwQuerySystemInformation with a NULL buffer to get size needed.
    //
    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH)
        return status;

    //
    // Allocate enough space for the module information.
    //
    pModuleInfo = (PSYSTEM_MODULE_INFORMATION) ExAllocatePoolWithTag(NonPagedPool, bufferSize,
                                                                     'ldoM' // A simple pool tag, e.g. "M0dl"
    );

    if (!pModuleInfo)
        return STATUS_INSUFFICIENT_RESOURCES;


    //
    // Query again with the allocated buffer.
    //
    status = ZwQuerySystemInformation(SystemModuleInformation, pModuleInfo, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status))
    {
        ExFreePool(pModuleInfo);
        return status;
    }

    //
    // The first entry in the returned module list is typically ntoskrnl.exe.
    // Because "Module[0]" is almost always the kernel, we set that as the result.
    // Alternatively, you could iterate and look for "ntoskrnl.exe" in ImageName.
    //
    if (pModuleInfo->Count > 0)
        *pBaseAddress = pModuleInfo->Module[0].ImageBase;


    //
    // Cleanup
    //
    ExFreePool(pModuleInfo);
    return STATUS_SUCCESS;
}

NTSTATUS read_memory(PEPROCESS target_process, void* source, void* target, size_t size)
{
    VIRTUALIZER_FALCON_TINY_START;
    KAPC_STATE ApcState;
    KeStackAttachProcess(target_process, &ApcState);

    memcpy_structure _{};
    _.destination = target;
    _.max_size = 0xFFFFFFFF;
    _.offset = 0;
    memset(_.pad, 0, sizeof(_.pad));
    _.error_flag = 0;

    static uintptr_t base = 0;

    if (!base)
        GetNtoskrnlBaseAddress((void**) &base);

    if (!base)
        return STATUS_UNSUCCESSFUL;

    static auto func = (PiDqSerializationWrite_t) (base + 0x9FFDE0);

    func(&_, source, (unsigned int) size);

    if (_.error_flag)
    {
        KeUnstackDetachProcess(&ApcState);
        return STATUS_UNSUCCESSFUL;
    }

    KeUnstackDetachProcess(&ApcState);

    VIRTUALIZER_FALCON_TINY_END;
    return STATUS_SUCCESS;
}

bool memory::ReadProcessVirtualMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size)
{
    if (!address || !buffer || !size || !pid)
        return false;

    SIZE_T bytes = 0;
    PEPROCESS process;

    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return false;

    return NT_SUCCESS(read_memory(process, address, buffer, size));
}
bool memory::WriteProcessVirtualMemory(HANDLE pid, PVOID sourceAddr, PVOID targetAddr, SIZE_T size)
{
    VIRTUALIZER_FALCON_TINY_START
    if (!sourceAddr || !targetAddr || !size)
        return false;

    PEPROCESS process;
    SIZE_T bytes = 0;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return false;

    const auto res = MmCopyVirtualMemory(PsGetCurrentProcess(), sourceAddr, process, targetAddr, size, KernelMode, &bytes);

    VIRTUALIZER_FALCON_TINY_END
    return res;
}
uintptr_t memory::GetProcessModuleBase(HANDLE pid)
{
    PEPROCESS process;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return 0;

    return reinterpret_cast<uintptr_t>(PsGetProcessSectionBaseAddress(process));
}
