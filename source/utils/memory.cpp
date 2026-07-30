#include "plato/utils/memory.hpp"

extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(_In_ PEPROCESS Process);

namespace
{
    constexpr uint64_t kPageSize = 0x1000;
    constexpr uint64_t kPageMask = kPageSize - 1;
    constexpr uint64_t kPageTableIndexMask = 0x1FF;
    constexpr uint64_t kPagePresent = 1;
    constexpr uint64_t kLargePage = 1ULL << 7;
    constexpr ACCESS_MASK kProcessQueryInformation = 0x0400;

    // Four-level x64 paging reserves bits 12-51 of a page-table entry for the physical frame number.
    constexpr uint64_t kPhysicalPageMask = 0x000F'FFFF'FFFF'F000ULL;
    constexpr uint64_t kTwoMegabytePageMask = kPhysicalPageMask & ~((1ULL << 21) - 1);
    constexpr uint64_t kOneGigabytePageMask = kPhysicalPageMask & ~((1ULL << 30) - 1);

    alignas(sizeof(LONG64)) volatile LONG64 g_lastPageTableRoot = 0;

    class LockedUserRange final
    {
    public:
        LockedUserRange() = default;

        ~LockedUserRange()
        {
            Reset();
        }

        LockedUserRange(const LockedUserRange&) = delete;
        LockedUserRange& operator=(const LockedUserRange&) = delete;

        NTSTATUS Lock(PEPROCESS process, PVOID address, SIZE_T size, LOCK_OPERATION operation)
        {
            if (!process || !address || !size || size > memory::kMaxTransferSize)
                return STATUS_INVALID_PARAMETER;

            m_mdl = IoAllocateMdl(address, static_cast<ULONG>(size), FALSE, FALSE, nullptr);
            if (!m_mdl)
                return STATUS_INSUFFICIENT_RESOURCES;

            KAPC_STATE apcState{};
            NTSTATUS status = STATUS_SUCCESS;

            KeStackAttachProcess(process, &apcState);
            __try
            {
                // The target buffer is a user-mode address in the attached process. Locking it prevents its
                // physical frames from being released or remapped while the PML4 search and physical copy run.
                MmProbeAndLockPages(m_mdl, UserMode, operation);
                m_locked = true;
            } __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
            }
            KeUnstackDetachProcess(&apcState);

            if (!NT_SUCCESS(status))
                Reset();

            return status;
        }

        PMDL GetMdl() const
        {
            return m_mdl;
        }

    private:
        void Reset()
        {
            if (m_locked)
            {
                MmUnlockPages(m_mdl);
                m_locked = false;
            }

            if (m_mdl)
            {
                IoFreeMdl(m_mdl);
                m_mdl = nullptr;
            }
        }

        PMDL m_mdl{};
        bool m_locked{};
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

    bool PageTableMapsLockedRange(uint64_t pageTableRoot, PMDL mdl)
    {
        if (!mdl)
            return false;

        const auto virtualAddress = reinterpret_cast<uint64_t>(MmGetMdlVirtualAddress(mdl));
        const SIZE_T byteCount = MmGetMdlByteCount(mdl);
        if (!byteCount || !IsCanonicalAddress(virtualAddress))
            return false;

        const SIZE_T pageCount = ADDRESS_AND_SIZE_TO_SPAN_PAGES(virtualAddress, byteCount);
        const PPFN_NUMBER pageFrames = MmGetMdlPfnArray(mdl);
        uint64_t virtualPage = virtualAddress & ~kPageMask;

        for (SIZE_T pageIndex = 0; pageIndex < pageCount; ++pageIndex)
        {
            uint64_t physicalAddress = 0;
            if (!TranslateVirtualAddress(pageTableRoot, virtualPage, &physicalAddress) ||
                (physicalAddress >> PAGE_SHIFT) != pageFrames[pageIndex])
                return false;

            virtualPage += kPageSize;
        }

        return true;
    }

    bool FindPageTableRoot(PMDL mdl, uint64_t* pageTableRoot)
    {
        if (!mdl || !pageTableRoot || KeGetCurrentIrql() != PASSIVE_LEVEL)
            return false;

        const auto cachedRoot =
                static_cast<uint64_t>(InterlockedCompareExchange64(&g_lastPageTableRoot, 0, 0));
        if (cachedRoot && PageTableMapsLockedRange(cachedRoot, mdl))
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
                if (PageTableMapsLockedRange(candidate, mdl))
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

    LockedUserRange lockedRange;
    uint64_t pageTableRoot = 0;
    const NTSTATUS status = lockedRange.Lock(process, address, size, IoReadAccess);
    const bool copied = NT_SUCCESS(status) && FindPageTableRoot(lockedRange.GetMdl(), &pageTableRoot) &&
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

    LockedUserRange lockedRange;
    uint64_t pageTableRoot = 0;
    const NTSTATUS status = IsReadableUserRange(process, targetAddr, size)
                                    ? lockedRange.Lock(process, targetAddr, size, IoReadAccess)
                                    : STATUS_ACCESS_DENIED;
    const bool copied = NT_SUCCESS(status) && FindPageTableRoot(lockedRange.GetMdl(), &pageTableRoot) &&
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
