#pragma once
#include <ntifs.h>


extern "C" NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);

namespace memory
{

	bool ReadProcessVirtualMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size);
	bool WriteProcessVirtualMemory(HANDLE pid, PVOID sourceAddr, PVOID targetAddr, SIZE_T size);
	uintptr_t GetProcessModuleBase(HANDLE pid);
}