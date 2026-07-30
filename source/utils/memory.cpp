#include "plato/utils/memory.hpp"

extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(_In_ PEPROCESS Process);
extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessPeb(_In_ PEPROCESS Process);

namespace
{
    constexpr uint64_t kPageSize = 0x1000;
    constexpr uint64_t kPageMask = kPageSize - 1;
    constexpr uint64_t kPageTableIndexMask = 0x1FF;
    constexpr uint64_t kPagePresent = 1;
    constexpr uint64_t kLargePage = 1ULL << 7;
    constexpr ACCESS_MASK kProcessQueryInformation = 0x0400;
    constexpr uint64_t kPebValidationOffset = 0x10;
    constexpr SIZE_T kValidationAnchorSize = 48;
    constexpr SIZE_T kMaxValidationAnchors = 1;

    // Four-level x64 paging reserves bits 12-51 of a page-table entry for the physical frame number.
    constexpr uint64_t kPhysicalPageMask = 0x000F'FFFF'FFFF'F000ULL;
    constexpr uint64_t kTwoMegabytePageMask = kPhysicalPageMask & ~((1ULL << 21) - 1);
    constexpr uint64_t kOneGigabytePageMask = kPhysicalPageMask & ~((1ULL << 30) - 1);

    alignas(sizeof(LONG64)) volatile LONG64 g_lastPageTableRoot = 0;

    struct ValidationAnchor
    {
        uint64_t virtualAddress{};
        SIZE_T size{};
        unsigned char bytes[kValidationAnchorSize]{};
    };

    struct PageTableValidation
    {
        ValidationAnchor anchors[kMaxValidationAnchors]{};
        SIZE_T count{};
    };

    bool IsCanonicalAddress(uint64_t address)
    {
        const uint64_t upperBits = address >> 48;
        return upperBits == 0 || upperBits == 0xFFFF;
    }

    bool IsReadableProtection(ULONG protection)
    {
        if (protection & PAGE_GUARD)
            return false;

        switch (protection & 0xFF)
        {
            case PAGE_READONLY:
            case PAGE_READWRITE:
            case PAGE_WRITECOPY:
            case PAGE_EXECUTE_READ:
            case PAGE_EXECUTE_READWRITE:
            case PAGE_EXECUTE_WRITECOPY:
                return true;
            default:
                return false;
        }
    }

    bool IsReadableUserRange(PEPROCESS process, PVOID address, SIZE_T size)
    {
        if (!process || !address || !size || KeGetCurrentIrql() != PASSIVE_LEVEL)
            return false;

        const auto rangeStart = reinterpret_cast<uintptr_t>(address);
        const auto highestUserAddress = reinterpret_cast<uintptr_t>(MmHighestUserAddress);
        if (rangeStart > highestUserAddress || size - 1 > highestUserAddress - rangeStart)
            return false;

        HANDLE processHandle = nullptr;
        const NTSTATUS openStatus =
                ObOpenObjectByPointer(process, OBJ_KERNEL_HANDLE, nullptr, kProcessQueryInformation, *PsProcessType,
                                      KernelMode, &processHandle);
        if (!NT_SUCCESS(openStatus))
            return false;

        const uintptr_t rangeEnd = rangeStart + size;
        uintptr_t currentAddress = rangeStart;
        bool readable = true;

        while (currentAddress < rangeEnd)
        {
            MEMORY_BASIC_INFORMATION memoryInformation{};
            const NTSTATUS queryStatus =
                    ZwQueryVirtualMemory(processHandle, reinterpret_cast<PVOID>(currentAddress),
                                         MemoryBasicInformation, &memoryInformation, sizeof(memoryInformation), nullptr);
            if (!NT_SUCCESS(queryStatus) || memoryInformation.State != MEM_COMMIT ||
                !IsReadableProtection(memoryInformation.Protect))
            {
                readable = false;
                break;
            }

            const auto regionStart = reinterpret_cast<uintptr_t>(memoryInformation.BaseAddress);
            if (!memoryInformation.RegionSize || regionStart > currentAddress ||
                regionStart > UINTPTR_MAX - memoryInformation.RegionSize)
            {
                readable = false;
                break;
            }

            const uintptr_t regionEnd = regionStart + memoryInformation.RegionSize;
            if (regionEnd <= currentAddress)
            {
                readable = false;
                break;
            }

            currentAddress = regionEnd < rangeEnd ? regionEnd : rangeEnd;
        }

        ZwClose(processHandle);
        return readable;
    }

    bool CopyProcessVirtualMemorySafely(PEPROCESS process, uint64_t virtualAddress, void* buffer, SIZE_T size)
    {
        if (!process || !virtualAddress || !buffer || !size || KeGetCurrentIrql() > APC_LEVEL)
            return false;

        KAPC_STATE apcState{};
        KeStackAttachProcess(process, &apcState);

        MM_COPY_ADDRESS source{};
        source.VirtualAddress = reinterpret_cast<PVOID>(virtualAddress);

        SIZE_T bytesCopied = 0;
        const NTSTATUS status =
                MmCopyMemory(buffer, source, size, MM_COPY_MEMORY_VIRTUAL, &bytesCopied);

        KeUnstackDetachProcess(&apcState);
        return NT_SUCCESS(status) && bytesCopied == size;
    }

    bool ValidateProcessVirtualRangeSafely(PEPROCESS process, PVOID address, SIZE_T size)
    {
        if (!process || !address || !size)
            return false;

        const auto rangeStart = reinterpret_cast<uint64_t>(address);
        const uint64_t rangeEnd = rangeStart + size;
        uint64_t currentAddress = rangeStart;
        unsigned char byte = 0;

        while (currentAddress < rangeEnd)
        {
            if (!CopyProcessVirtualMemorySafely(process, currentAddress, &byte, sizeof(byte)))
                return false;

            const uint64_t nextPage = (currentAddress & ~kPageMask) + kPageSize;
            if (nextPage <= currentAddress || nextPage >= rangeEnd)
                break;

            currentAddress = nextPage;
        }

        const uint64_t lastAddress = rangeEnd - 1;
        return lastAddress == currentAddress ||
               CopyProcessVirtualMemorySafely(process, lastAddress, &byte, sizeof(byte));
    }

    bool ReadPhysicalMemory(uint64_t physicalAddress, void* buffer, SIZE_T size)
    {
        MM_COPY_ADDRESS source{};
        source.PhysicalAddress.QuadPart = static_cast<LONGLONG>(physicalAddress);

        SIZE_T bytesCopied = 0;
        const NTSTATUS status = MmCopyMemory(buffer, source, size, MM_COPY_MEMORY_PHYSICAL, &bytesCopied);
        return NT_SUCCESS(status) && bytesCopied == size;
    }

    bool ReadPageTableEntry(uint64_t tablePhysicalAddress, uint64_t index, uint64_t* entry)
    {
        return ReadPhysicalMemory(tablePhysicalAddress + index * sizeof(*entry), entry, sizeof(*entry));
    }

    bool TranslateVirtualAddress(uint64_t pageTableRoot, uint64_t virtualAddress, uint64_t* physicalAddress)
    {
        if (!(pageTableRoot & kPhysicalPageMask) || (pageTableRoot & kPageMask) ||
            !IsCanonicalAddress(virtualAddress) || !physicalAddress)
            return false;

        const uint64_t pml4Index = (virtualAddress >> 39) & kPageTableIndexMask;
        const uint64_t pdptIndex = (virtualAddress >> 30) & kPageTableIndexMask;
        const uint64_t pdIndex = (virtualAddress >> 21) & kPageTableIndexMask;
        const uint64_t ptIndex = (virtualAddress >> 12) & kPageTableIndexMask;

        uint64_t pml4e = 0;
        if (!ReadPageTableEntry(pageTableRoot, pml4Index, &pml4e) || !(pml4e & kPagePresent) ||
            (pml4e & kLargePage))
            return false;

        uint64_t pdpte = 0;
        if (!ReadPageTableEntry(pml4e & kPhysicalPageMask, pdptIndex, &pdpte) || !(pdpte & kPagePresent))
            return false;

        if (pdpte & kLargePage)
        {
            *physicalAddress = (pdpte & kOneGigabytePageMask) | (virtualAddress & ((1ULL << 30) - 1));
            return true;
        }

        uint64_t pde = 0;
        if (!ReadPageTableEntry(pdpte & kPhysicalPageMask, pdIndex, &pde) || !(pde & kPagePresent))
            return false;

        if (pde & kLargePage)
        {
            *physicalAddress = (pde & kTwoMegabytePageMask) | (virtualAddress & ((1ULL << 21) - 1));
            return true;
        }

        uint64_t pte = 0;
        if (!ReadPageTableEntry(pde & kPhysicalPageMask, ptIndex, &pte) || !(pte & kPagePresent))
            return false;

        *physicalAddress = (pte & kPhysicalPageMask) | (virtualAddress & kPageMask);
        return true;
    }

    bool CopyTranslatedPhysicalMemory(uint64_t pageTableRoot, uint64_t virtualAddress, void* buffer, SIZE_T size,
                                      bool write);

    bool CaptureValidationAnchor(PEPROCESS process, uint64_t virtualAddress, SIZE_T size,
                                 PageTableValidation* validation)
    {
        if (!process || !virtualAddress || !size || !validation || validation->count >= kMaxValidationAnchors)
            return false;

        ValidationAnchor& anchor = validation->anchors[validation->count];
        anchor.virtualAddress = virtualAddress;
        anchor.size = size < kValidationAnchorSize ? size : kValidationAnchorSize;

        if (!CopyProcessVirtualMemorySafely(process, anchor.virtualAddress, anchor.bytes, anchor.size))
            return false;

        ++validation->count;
        return true;
    }

    bool CapturePageTableValidation(PEPROCESS process, PageTableValidation* validation)
    {
        if (!process || !validation)
            return false;

        const auto pebAddress = reinterpret_cast<uint64_t>(PsGetProcessPeb(process));
        const auto highestUserAddress = reinterpret_cast<uint64_t>(MmHighestUserAddress);
        if (!pebAddress || pebAddress > highestUserAddress ||
            kPebValidationOffset > highestUserAddress - pebAddress)
            return false;

        const uint64_t anchorAddress = pebAddress + kPebValidationOffset;
        if (kValidationAnchorSize - 1 > highestUserAddress - anchorAddress)
            return false;

        return CaptureValidationAnchor(process, anchorAddress, kValidationAnchorSize, validation);
    }

    bool PageTableMatchesValidation(uint64_t pageTableRoot, const PageTableValidation& validation)
    {
        if (!validation.count)
            return false;

        unsigned char bytes[kValidationAnchorSize]{};
        for (SIZE_T index = 0; index < validation.count; ++index)
        {
            const ValidationAnchor& anchor = validation.anchors[index];
            if (!CopyTranslatedPhysicalMemory(pageTableRoot, anchor.virtualAddress, bytes, anchor.size, false) ||
                RtlCompareMemory(bytes, anchor.bytes, anchor.size) != anchor.size)
                return false;
        }

        return true;
    }

    bool FindPageTableRoot(const PageTableValidation& validation, uint64_t* pageTableRoot)
    {
        if (!validation.count || !pageTableRoot || KeGetCurrentIrql() != PASSIVE_LEVEL)
            return false;

        const auto cachedRoot =
                static_cast<uint64_t>(InterlockedCompareExchange64(&g_lastPageTableRoot, 0, 0));
        if (cachedRoot && PageTableMatchesValidation(cachedRoot, validation))
        {
            *pageTableRoot = cachedRoot;
            return true;
        }

        PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
        if (!ranges)
            return false;

        uint64_t foundRoot = 0;

        for (PPHYSICAL_MEMORY_RANGE range = ranges; range->NumberOfBytes.QuadPart != 0 && !foundRoot; ++range)
        {
            if (range->BaseAddress.QuadPart < 0 || range->NumberOfBytes.QuadPart < 0)
                continue;

            const uint64_t base = static_cast<uint64_t>(range->BaseAddress.QuadPart);
            const uint64_t length = static_cast<uint64_t>(range->NumberOfBytes.QuadPart);
            if (length < kPageSize || base > UINT64_MAX - length || base > UINT64_MAX - kPageMask)
                continue;

            const uint64_t rangeEnd = base + length;
            const uint64_t firstPage = (base + kPageMask) & ~kPageMask;
            const uint64_t lastPage = rangeEnd - kPageSize;

            for (uint64_t candidate = firstPage; candidate <= lastPage;)
            {
                if (PageTableMatchesValidation(candidate, validation))
                {
                    foundRoot = candidate;
                    break;
                }

                if (lastPage - candidate < kPageSize)
                    break;

                candidate += kPageSize;
            }
        }

        ExFreePool(ranges);

        if (!foundRoot)
            return false;

        InterlockedExchange64(&g_lastPageTableRoot, static_cast<LONG64>(foundRoot));
        *pageTableRoot = foundRoot;
        return true;
    }

    bool WritePhysicalMemory(uint64_t physicalAddress, const void* buffer, SIZE_T size)
    {
        const uint64_t physicalPage = physicalAddress & ~kPageMask;
        const SIZE_T pageOffset = static_cast<SIZE_T>(physicalAddress & kPageMask);
        const SIZE_T mapSize = pageOffset + size;

        PHYSICAL_ADDRESS pageAddress{};
        pageAddress.QuadPart = static_cast<LONGLONG>(physicalPage);

        PVOID mappedPage = MmMapIoSpace(pageAddress, mapSize, MmCached);
        if (!mappedPage)
            return false;

        RtlCopyMemory(static_cast<unsigned char*>(mappedPage) + pageOffset, buffer, size);
        MmUnmapIoSpace(mappedPage, mapSize);
        return true;
    }

    bool CopyTranslatedPhysicalMemory(uint64_t pageTableRoot, uint64_t virtualAddress, void* buffer, SIZE_T size,
                                      bool write)
    {
        auto* bytes = static_cast<unsigned char*>(buffer);

        while (size)
        {
            uint64_t physicalAddress = 0;
            if (!TranslateVirtualAddress(pageTableRoot, virtualAddress, &physicalAddress))
                return false;

            const SIZE_T bytesToPageBoundary = static_cast<SIZE_T>(kPageSize - (physicalAddress & kPageMask));
            const SIZE_T chunkSize = size < bytesToPageBoundary ? size : bytesToPageBoundary;
            const bool copied = write ? WritePhysicalMemory(physicalAddress, bytes, chunkSize)
                                      : ReadPhysicalMemory(physicalAddress, bytes, chunkSize);
            if (!copied)
                return false;

            bytes += chunkSize;
            virtualAddress += chunkSize;
            size -= chunkSize;
        }

        return true;
    }
} // namespace

bool memory::ReadProcessVirtualMemory(HANDLE pid, PVOID address, PVOID buffer, SIZE_T size)
{
    if (!pid || !address || !buffer || !size || size > kMaxTransferSize)
        return false;

    PEPROCESS process = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return false;

    PageTableValidation validation{};
    uint64_t pageTableRoot = 0;
    const bool copied = IsReadableUserRange(process, address, size) &&
                        ValidateProcessVirtualRangeSafely(process, address, size) &&
                        CapturePageTableValidation(process, &validation) &&
                        FindPageTableRoot(validation, &pageTableRoot) &&
                        CopyTranslatedPhysicalMemory(pageTableRoot, reinterpret_cast<uintptr_t>(address), buffer, size,
                                                     false);

    ObDereferenceObject(process);
    return copied;
}

bool memory::ForceWriteProcessVirtualMemory(HANDLE pid, PVOID sourceAddr, PVOID targetAddr, SIZE_T size)
{
    if (!pid || !sourceAddr || !targetAddr || !size || size > kMaxTransferSize)
        return false;

    PEPROCESS process = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return false;

    PageTableValidation validation{};
    uint64_t pageTableRoot = 0;
    const bool copied = IsReadableUserRange(process, targetAddr, size) &&
                        ValidateProcessVirtualRangeSafely(process, targetAddr, size) &&
                        CapturePageTableValidation(process, &validation) &&
                        FindPageTableRoot(validation, &pageTableRoot) &&
                        PageTableMatchesValidation(pageTableRoot, validation) &&
                        CopyTranslatedPhysicalMemory(pageTableRoot, reinterpret_cast<uintptr_t>(targetAddr), sourceAddr,
                                                     size, true);

    ObDereferenceObject(process);
    return copied;
}

uintptr_t memory::GetProcessModuleBase(HANDLE pid)
{
    PEPROCESS process = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return 0;

    const auto baseAddress = reinterpret_cast<uintptr_t>(PsGetProcessSectionBaseAddress(process));
    ObDereferenceObject(process);
    return baseAddress;
}
