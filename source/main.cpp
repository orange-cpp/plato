#include "utils/memory.h"
#include <VirtualizerSDK.h>
#include "ksocket/berkeley.h"
#include "ksocket/ksocket.h"
#include <StealthCodeArea.h>

STEALTH_AUX_FUNCTION

void CodeVirtualizerStealthArea()
{
    STEALTH_AREA_START
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_START
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_START
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_START
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_CHUNK
    STEALTH_AREA_END
}

typedef unsigned char uint8_t;

enum class OPERATION
{
    READ,
    WRITE,
    PROCESS_BASE,
};

class BasePacket
{
public:
    OPERATION m_iOperation;
};

class ReadMemoryOperation final : public BasePacket
{
public:
    uintptr_t m_addr;
    uintptr_t m_procId;
    size_t m_iSize;
};



//--------------------------------------------------------------------------------------
// Forward declarations
//--------------------------------------------------------------------------------------
static NTSTATUS HandleClientSocket(int client_sockfd);
static bool HandlePacket(BasePacket* pPacket, int client_sockfd);
static void HandleReadOperation(ReadMemoryOperation* pReadParam, int client_sockfd);
static void HandleWriteOperation(ReadMemoryOperation* pWriteParam, int client_sockfd);
static void HandleProcessBaseOperation(ReadMemoryOperation* pBaseParam, int client_sockfd);

//--------------------------------------------------------------------------------------
// Sets up the server socket and returns the listening socket file descriptor,
// or a negative value on failure
//--------------------------------------------------------------------------------------
static int SetupServerSocket(uint16_t port)
{
    VIRTUALIZER_FALCON_TINY_START
    KsInitialize(); // Initialize your ksocket or other low-level network setup

    int server_sockfd = socket_listen(AF_INET, SOCK_STREAM, 0);
    if (server_sockfd < 0)
        return -1;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_sockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
        return -1;

    VIRTUALIZER_FALCON_TINY_END
    return server_sockfd;
}

//--------------------------------------------------------------------------------------
// Main server loop: listens and accepts incoming connections,
// then dispatches each client to be handled
//--------------------------------------------------------------------------------------
[[noreturn]] static void RunServerLoop(int server_sockfd)
{
    while (true)
    {
        // Allow up to 1 connection in the queue
        listen(server_sockfd, 1);

        sockaddr_in clientAddr{};
        socklen_t addrlen = sizeof(clientAddr);

        // Accept a client connection
        const int client_sockfd = accept(server_sockfd, reinterpret_cast<sockaddr*>(&clientAddr), &addrlen);

        if (client_sockfd < 0)
        {
            // If accept fails, you may break or continue depending on policy
            continue;
        }
        // Handle the client until disconnection or error
        HandleClientSocket(client_sockfd);

        // Close or clean up the client socket if needed here
        // (If ksocket has its own close function, use it)
        // e.g., ksocket::close(client_sockfd);


    }
}

//--------------------------------------------------------------------------------------
// Handles all communication with the client socket: receives packets, processes them
//--------------------------------------------------------------------------------------
static NTSTATUS HandleClientSocket(int client_sockfd)
{

    while (true)
    {
        size_t szSizeOfPacket = 0;

        // First receive the size of the incoming packet
        if (recv(client_sockfd, &szSizeOfPacket, sizeof(szSizeOfPacket), 0) <= 0)
            break; // Client disconnected or error

        // Allocate space for the packet
        const auto pPacket = static_cast<BasePacket*>(ExAllocatePoolWithTag(NonPagedPool, szSizeOfPacket, 'pac'));
        if (!pPacket)
            break; // Allocation failed

        // Receive the actual packet
        if (recv(client_sockfd, pPacket, szSizeOfPacket, 0) <= 0)
        {
            ExFreePoolWithTag(pPacket, 0);
            break; // Client disconnected or error
        }

        // Process the packet and free it
        const bool success = HandlePacket(pPacket, client_sockfd);
        ExFreePoolWithTag(pPacket, 0);


        if (!success)
            break;

    }

    return STATUS_SUCCESS;
}

//--------------------------------------------------------------------------------------
// Routes a received packet to the appropriate handler based on operation
// Returns false if an unknown operation is encountered or if an error occurs
//--------------------------------------------------------------------------------------
static bool HandlePacket(BasePacket* pPacket, int client_sockfd)
{
    switch (pPacket->m_iOperation)
    {
        case OPERATION::READ:
        {
            auto pReadParam = static_cast<ReadMemoryOperation*>(pPacket);
            HandleReadOperation(pReadParam, client_sockfd);
            return true;
        }
        case OPERATION::WRITE:
        {
            auto pWriteParam = static_cast<ReadMemoryOperation*>(pPacket);
            HandleWriteOperation(pWriteParam, client_sockfd);
            return true;
        }
        case OPERATION::PROCESS_BASE:
        {
            auto pBaseParam = static_cast<ReadMemoryOperation*>(pPacket);
            HandleProcessBaseOperation(pBaseParam, client_sockfd);
            return true;
        }
    }
    // Unknown operation: send failure response
    constexpr bool bStatus = false;
    constexpr size_t szStatusSize = sizeof(bStatus);

    send(client_sockfd, &szStatusSize, sizeof(szStatusSize), 0);
    send(client_sockfd, &bStatus, 1, 0);

    return false;
}

//--------------------------------------------------------------------------------------
// READ operation handling
//--------------------------------------------------------------------------------------
static void HandleReadOperation(ReadMemoryOperation* pReadParam, int client_sockfd)
{

    // Allocate buffer to hold the data we’ll read
    auto pSendBuffer = ExAllocatePoolWithTag(NonPagedPool, pReadParam->m_iSize, 'pac');
    if (!pSendBuffer)
        return;

    RtlZeroMemory(pSendBuffer, pReadParam->m_iSize);

    // Read data from target process memory
    memory::ReadProcessVirtualMemory(reinterpret_cast<HANDLE>(pReadParam->m_procId),
                                     reinterpret_cast<PVOID>(pReadParam->m_addr), pSendBuffer, pReadParam->m_iSize);

    // Send the size of the data and then the data
    send(client_sockfd, &pReadParam->m_iSize, sizeof(size_t), 0);
    send(client_sockfd, pSendBuffer, pReadParam->m_iSize, 0);

    ExFreePoolWithTag(pSendBuffer, 0);

}

//--------------------------------------------------------------------------------------
// WRITE operation handling
//--------------------------------------------------------------------------------------
static void HandleWriteOperation(ReadMemoryOperation* pWriteParam, int client_sockfd)
{
    // Allocate buffer to hold incoming data
    auto pWriteBuffer = ExAllocatePoolWithTag(NonPagedPool, pWriteParam->m_iSize, 'pac');
    if (!pWriteBuffer)
        return;

    // Receive data that needs to be written to the target process memory
    recv(client_sockfd, pWriteBuffer, pWriteParam->m_iSize, 0);

    memory::WriteProcessVirtualMemory(reinterpret_cast<HANDLE>(pWriteParam->m_procId), pWriteBuffer,
                                      reinterpret_cast<PVOID>(pWriteParam->m_addr), pWriteParam->m_iSize);

    // Send a success response
    constexpr bool bStatus = true;
    constexpr size_t szStatusSize = sizeof(bStatus);

    send(client_sockfd, &szStatusSize, sizeof(szStatusSize), 0);
    send(client_sockfd, &bStatus, 1, 0);

    ExFreePoolWithTag(pWriteBuffer, 0);
}

//--------------------------------------------------------------------------------------
// PROCESS_BASE operation handling
//--------------------------------------------------------------------------------------
static void HandleProcessBaseOperation(ReadMemoryOperation* pBaseParam, int client_sockfd)
{
    // Retrieve the base address of the target process's main module
    const auto procBase = memory::GetProcessModuleBase(reinterpret_cast<HANDLE>(pBaseParam->m_procId));

    constexpr size_t baseSize = sizeof(procBase);

    // Send back the base address
    send(client_sockfd, &baseSize, sizeof(size_t), 0);
    send(client_sockfd, &procBase, sizeof(procBase), 0);

}

//--------------------------------------------------------------------------------------
// Kernel thread entry point
//--------------------------------------------------------------------------------------
[[noreturn]]
NTSTATUS ThreadFunction([[maybe_unused]] _In_ PVOID StartContext)
{
    int server_sockfd = SetupServerSocket(7653);
    if (server_sockfd < 0)
    {
        // Failed to set up server socket – do error handling as needed
        // Typically you'd terminate the thread or similar
        KeBugCheck(0);
    }
    // 2. Start looping and accepting connections
    RunServerLoop(server_sockfd);

}

//--------------------------------------------------------------------------------------
// DriverEntry
//--------------------------------------------------------------------------------------
extern "C" DRIVER_INITIALIZE DriverEntry;
extern "C" NTSTATUS DriverEntry([[maybe_unused]] _In_ PDRIVER_OBJECT driverObject,
                                [[maybe_unused]] _In_ PUNICODE_STRING registryPath)
{
    VIRTUALIZER_FALCON_TINY_START

    if (reinterpret_cast<uintptr_t>(driverObject) == 0x1335)
        CodeVirtualizerStealthArea();

    HANDLE threadHandle;
    PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr,
                         reinterpret_cast<PKSTART_ROUTINE>(ThreadFunction), nullptr);

    VIRTUALIZER_FALCON_TINY_END
    return STATUS_SUCCESS;
}
