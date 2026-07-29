#include "plato/utils/memory.hpp"

#include <intrin.h>

extern "C" NTKERNELAPI PVOID NTAPI PsGetProcessSectionBaseAddress(_In_ PEPROCESS Process);

namespace
{
    constexpr uint64_t kPageSize = 0x1000;
    constexpr uint64_t kPageMask = kPageSize - 1;
    constexpr uint64_t kPageTableIndexMask = 0x1FF;
    constexpr uint64_t kPagePresent = 1;
    constexpr uint64_t kLargePage = 1ULL << 7;

    // Four-level x64 paging reserves bits 12-51 of a page-table entry for the physical frame number.
    constexpr uint64_t kPhysicalPageMask = 0x000F'FFFF'FFFF'F000ULL;
    constexpr uint64_t kTwoMegabytePageMask = kPhysicalPageMask & ~((1ULL << 21) - 1);
    constexpr uint64_t kOneGigabytePageMask = kPhysicalPageMask & ~((1ULL << 30) - 1);

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

        NTSTATUS Lock(PEPROCESS process, PVOID address, SIZE_T size, LOCK_OPERATION operation, uint64_t* cr3)
        {
            if (!process || !address || !size || size > memory::kMaxTransferSize || !cr3)
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
                // physical frames from being released or remapped while the CR3 walk and physical copy run.
                MmProbeAndLockPages(m_mdl, UserMode, operation);
                m_locked = true;

                *cr3 = __readcr3() & kPhysicalPageMask;
                if (!*cr3)
                    status = STATUS_UNSUCCESSFUL;
            } __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
            }
            KeUnstackDetachProcess(&apcState);

            if (!NT_SUCCESS(status))
                Reset();

            return status;
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

    bool TranslateVirtualAddress(uint64_t cr3, uint64_t virtualAddress, uint64_t* physicalAddress)
    {
        if (!IsCanonicalAddress(virtualAddress) || !physicalAddress)
            return false;

        const uint64_t pml4Index = (virtualAddress >> 39) & kPageTableIndexMask;
        const uint64_t pdptIndex = (virtualAddress >> 30) & kPageTableIndexMask;
        const uint64_t pdIndex = (virtualAddress >> 21) & kPageTableIndexMask;
        const uint64_t ptIndex = (virtualAddress >> 12) & kPageTableIndexMask;

        uint64_t pml4e = 0;
        if (!ReadPageTableEntry(cr3, pml4Index, &pml4e) || !(pml4e & kPagePresent))
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

    bool CopyTranslatedPhysicalMemory(uint64_t cr3, uint64_t virtualAddress, void* buffer, SIZE_T size, bool write)
    {
        auto* bytes = static_cast<unsigned char*>(buffer);

        while (size)
        {
            uint64_t physicalAddress = 0;
            if (!TranslateVirtualAddress(cr3, virtualAddress, &physicalAddress))
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
    uint64_t cr3 = 0;
    const NTSTATUS status = lockedRange.Lock(process, address, size, IoReadAccess, &cr3);
    const bool copied = NT_SUCCESS(status) &&
                        CopyTranslatedPhysicalMemory(cr3, reinterpret_cast<uintptr_t>(address), buffer, size, false);

    ObDereferenceObject(process);
    return copied;
}

bool memory::WriteProcessVirtualMemory(HANDLE pid, PVOID sourceAddr, PVOID targetAddr, SIZE_T size)
{
    if (!pid || !sourceAddr || !targetAddr || !size || size > kMaxTransferSize)
        return false;

    PEPROCESS process = nullptr;
    if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
        return false;

    LockedUserRange lockedRange;
    uint64_t cr3 = 0;
    const NTSTATUS status = lockedRange.Lock(process, targetAddr, size, IoWriteAccess, &cr3);
    const bool copied = NT_SUCCESS(status) && CopyTranslatedPhysicalMemory(cr3, reinterpret_cast<uintptr_t>(targetAddr),
                                                                           sourceAddr, size, true);

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
