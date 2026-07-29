#pragma once

#include <cstdint>
#include <ntifs.h>

namespace memory
{
    inline constexpr SIZE_T kMaxTransferSize = 1024 * 1024;

    bool ReadProcessVirtualMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size);
    bool WriteProcessVirtualMemory(HANDLE pid, PVOID sourceAddr, PVOID targetAddr, SIZE_T size);
    uintptr_t GetProcessModuleBase(HANDLE pid);
} // namespace memory
