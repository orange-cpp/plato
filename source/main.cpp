#include "plato/utils/memory.hpp"
#include "plato/utils/mouse.hpp"

#include <ksocket/berkeley.h>
#include <ksocket/ksocket.h>
typedef unsigned char uint8_t;

enum class OPERATION
{
    READ,
    WRITE_FORCE,
    PROCESS_BASE,
    MOVE_MOUSE_RELATIVE,
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

class MouseMoveRelativeOperation final : public BasePacket
{
public:
    LONG m_x;
    LONG m_y;
};


//--------------------------------------------------------------------------------------
// Forward declarations
//--------------------------------------------------------------------------------------
static NTSTATUS HandleClientSocket(int client_sockfd);

class ClientBuffer final
{
public:
    ~ClientBuffer()
    {
        if (m_data)
            ExFreePoolWithTag(m_data, 'pac');
    }

    bool EnsureCapacity(size_t size)
    {
        if (!size || size > memory::kMaxTransferSize)
            return false;

        if (size <= m_capacity)
            return true;

        auto newData = ExAllocatePoolWithTag(NonPagedPool, size, 'pac');
        if (!newData)
            return false;

        if (m_data)
            ExFreePoolWithTag(m_data, 'pac');

        m_data = newData;
        m_capacity = size;
        return true;
    }

    PVOID Data() const
    {
        return m_data;
    }

private:
    PVOID m_data{};
    size_t m_capacity{};
};

static bool ReceiveAll(int client_sockfd, void* buffer, size_t size)
{
    auto* bytes = static_cast<unsigned char*>(buffer);

    while (size)
    {
        const int received = recv(client_sockfd, bytes, size, 0);
        if (received <= 0)
            return false;

        bytes += received;
        size -= static_cast<size_t>(received);
    }

    return true;
}

static bool SendAll(int client_sockfd, const void* buffer, size_t size)
{
    auto* bytes = static_cast<const unsigned char*>(buffer);

    while (size)
    {
        const int sent = send(client_sockfd, bytes, size, 0);
        if (sent <= 0)
            return false;

        bytes += sent;
        size -= static_cast<size_t>(sent);
    }

    return true;
}

static bool HandleReadOperation(const ReadMemoryOperation* pReadParam, int client_sockfd, ClientBuffer& buffer);
static bool HandleForceWriteOperation(const ReadMemoryOperation* pWriteParam, int client_sockfd, ClientBuffer& buffer);
static bool HandleProcessBaseOperation(const ReadMemoryOperation* pBaseParam, int client_sockfd);
static bool HandleMouseMoveRelativeOperation(const MouseMoveRelativeOperation* pMoveParam, int client_sockfd);

//--------------------------------------------------------------------------------------
// Sets up the server socket and returns the listening socket file descriptor,
// or a negative value on failure
//--------------------------------------------------------------------------------------
static int SetupServerSocket(uint16_t port)
{
    KsInitialize(); // Initialize your ksocket or other low-level network setup

    int server_sockfd = socket_listen(AF_INET, SOCK_STREAM, 0);
    if (server_sockfd < 0)
        return -1;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(server_sockfd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0)
    {
        closesocket(server_sockfd);
        return -1;
    }

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

        closesocket(client_sockfd);
    }
}

//--------------------------------------------------------------------------------------
// Handles all communication with the client socket: receives packets, processes them
//--------------------------------------------------------------------------------------
static NTSTATUS HandleClientSocket(int client_sockfd)
{
    ClientBuffer buffer;

    while (true)
    {
        size_t szSizeOfPacket = 0;

        // First receive the size of the incoming packet
        if (!ReceiveAll(client_sockfd, &szSizeOfPacket, sizeof(szSizeOfPacket)))
            break; // Client disconnected or error

        BasePacket packetHeader{};
        if (!ReceiveAll(client_sockfd, &packetHeader, sizeof(packetHeader)))
            break; // Client disconnected or error

        bool success = false;

        switch (packetHeader.m_iOperation)
        {
            case OPERATION::READ:
            case OPERATION::WRITE_FORCE:
            case OPERATION::PROCESS_BASE:
            {
                if (szSizeOfPacket != sizeof(ReadMemoryOperation))
                    break;

                ReadMemoryOperation packet{};
                packet.m_iOperation = packetHeader.m_iOperation;
                if (!ReceiveAll(client_sockfd, reinterpret_cast<unsigned char*>(&packet) + sizeof(packetHeader),
                                sizeof(packet) - sizeof(packetHeader)))
                    return STATUS_SUCCESS;

                if (packet.m_iOperation == OPERATION::READ)
                    success = HandleReadOperation(&packet, client_sockfd, buffer);
                else if (packet.m_iOperation == OPERATION::WRITE_FORCE)
                    success = HandleForceWriteOperation(&packet, client_sockfd, buffer);
                else
                    success = HandleProcessBaseOperation(&packet, client_sockfd);
                break;
            }
            case OPERATION::MOVE_MOUSE_RELATIVE:
            {
                if (szSizeOfPacket != sizeof(MouseMoveRelativeOperation))
                    break;

                MouseMoveRelativeOperation packet{};
                packet.m_iOperation = packetHeader.m_iOperation;
                if (!ReceiveAll(client_sockfd, reinterpret_cast<unsigned char*>(&packet) + sizeof(packetHeader),
                                sizeof(packet) - sizeof(packetHeader)))
                    return STATUS_SUCCESS;

                success = HandleMouseMoveRelativeOperation(&packet, client_sockfd);
                break;
            }
        }

        if (!success)
        {
            constexpr bool bStatus = false;
            constexpr size_t szStatusSize = sizeof(bStatus);

            SendAll(client_sockfd, &szStatusSize, sizeof(szStatusSize));
            SendAll(client_sockfd, &bStatus, sizeof(bStatus));
            break;
        }
    }

    return STATUS_SUCCESS;
}

//--------------------------------------------------------------------------------------
// READ operation handling
//--------------------------------------------------------------------------------------
static bool HandleReadOperation(const ReadMemoryOperation* pReadParam, int client_sockfd, ClientBuffer& buffer)
{
    // Reuse the connection buffer to hold the data we’ll read
    if (!buffer.EnsureCapacity(pReadParam->m_iSize))
        return false;

    auto pSendBuffer = buffer.Data();
    RtlZeroMemory(pSendBuffer, pReadParam->m_iSize);

    // Read data from target process memory
    if (!memory::ReadProcessVirtualMemory(reinterpret_cast<HANDLE>(pReadParam->m_procId),
                                          reinterpret_cast<PVOID>(pReadParam->m_addr), pSendBuffer,
                                          pReadParam->m_iSize))
    {
        constexpr size_t responseSize = 0;
        return SendAll(client_sockfd, &responseSize, sizeof(responseSize));
    }

    // Send the size of the data and then the data
    return SendAll(client_sockfd, &pReadParam->m_iSize, sizeof(pReadParam->m_iSize)) &&
           SendAll(client_sockfd, pSendBuffer, pReadParam->m_iSize);
}

//--------------------------------------------------------------------------------------
// WRITE_FORCE operation handling
//--------------------------------------------------------------------------------------
static bool HandleForceWriteOperation(const ReadMemoryOperation* pWriteParam, int client_sockfd, ClientBuffer& buffer)
{
    // Reuse the connection buffer to hold incoming data
    if (!buffer.EnsureCapacity(pWriteParam->m_iSize))
        return false;

    auto pWriteBuffer = buffer.Data();
    // Receive data that needs to be written to the target process memory
    if (!ReceiveAll(client_sockfd, pWriteBuffer, pWriteParam->m_iSize))
        return false;

    const bool bStatus =
            memory::ForceWriteProcessVirtualMemory(reinterpret_cast<HANDLE>(pWriteParam->m_procId), pWriteBuffer,
                                                   reinterpret_cast<PVOID>(pWriteParam->m_addr), pWriteParam->m_iSize);

    constexpr size_t szStatusSize = sizeof(bStatus);

    return SendAll(client_sockfd, &szStatusSize, sizeof(szStatusSize)) &&
           SendAll(client_sockfd, &bStatus, sizeof(bStatus));
}

//--------------------------------------------------------------------------------------
// PROCESS_BASE operation handling
//--------------------------------------------------------------------------------------
static bool HandleProcessBaseOperation(const ReadMemoryOperation* pBaseParam, int client_sockfd)
{
    // Retrieve the base address of the target process's main module
    const auto procBase = memory::GetProcessModuleBase(reinterpret_cast<HANDLE>(pBaseParam->m_procId));

    constexpr size_t baseSize = sizeof(procBase);

    // Send back the base address
    return SendAll(client_sockfd, &baseSize, sizeof(baseSize)) && SendAll(client_sockfd, &procBase, sizeof(procBase));
}

//--------------------------------------------------------------------------------------
// MOUSE_MOVE_RELATIVE operation handling
//--------------------------------------------------------------------------------------
static bool HandleMouseMoveRelativeOperation(const MouseMoveRelativeOperation* pMoveParam, int client_sockfd)
{
    const bool bStatus = mouse::MoveRelative(pMoveParam->m_x, pMoveParam->m_y);

    constexpr size_t szStatusSize = sizeof(bStatus);

    return SendAll(client_sockfd, &szStatusSize, sizeof(szStatusSize)) &&
           SendAll(client_sockfd, &bStatus, sizeof(bStatus));
}

//--------------------------------------------------------------------------------------
// Kernel thread entry point
//--------------------------------------------------------------------------------------
[[noreturn]]
NTSTATUS ThreadFunction([[maybe_unused]] _In_ PVOID StartContext)
{
    const int server_sockfd = SetupServerSocket(7653);
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
    HANDLE threadHandle;
    const NTSTATUS status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr,
                                                 reinterpret_cast<PKSTART_ROUTINE>(ThreadFunction), nullptr);
    if (!NT_SUCCESS(status))
        return status;

    ZwClose(threadHandle);
    return STATUS_SUCCESS;
}
