#include "plato/driver_client.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <tlhelp32.h>

#include <algorithm>
#include <cwchar>
#include <limits>
#include <mutex>
#include <string>

namespace
{
    constexpr std::size_t kMaxTransferSize = 1024 * 1024;

    enum class Operation : std::uint32_t
    {
        Read,
        WriteForce,
        ProcessBase,
        MoveMouseRelative,
    };

    struct MemoryPacket
    {
        Operation operation{};
        std::uint32_t reserved{};
        std::uint64_t address{};
        std::uint64_t processId{};
        std::uint64_t size{};
    };

    struct MouseMovePacket
    {
        Operation operation{};
        std::int32_t x{};
        std::int32_t y{};
    };

    static_assert(sizeof(std::uintptr_t) == sizeof(std::uint64_t), "plato's driver protocol requires x64");
    static_assert(sizeof(Operation) == sizeof(std::uint32_t));
    static_assert(sizeof(MemoryPacket) == 32);
    static_assert(sizeof(MouseMovePacket) == 12);

    std::uint64_t FindProcessId(std::string_view processName)
    {
        if (processName.empty() || processName.size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
            return 0;

        const int nameSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, processName.data(),
                                                 static_cast<int>(processName.size()), nullptr, 0);
        if (nameSize <= 0)
            return 0;

        std::wstring expectedName(static_cast<std::size_t>(nameSize), L'\0');
        if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, processName.data(), static_cast<int>(processName.size()),
                                expectedName.data(), nameSize) != nameSize)
            return 0;

        if (expectedName.size() < 4 || _wcsicmp(expectedName.c_str() + expectedName.size() - 4, L".exe") != 0)
            expectedName += L".exe";

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE)
            return 0;

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);

        std::uint64_t processId = 0;
        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                if (_wcsicmp(entry.szExeFile, expectedName.c_str()) == 0)
                {
                    processId = entry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
        return processId;
    }
} // namespace

struct plato::DriverClient::Impl
{
    Impl()
    {
        WSADATA data{};
        winsockInitialized = WSAStartup(MAKEWORD(2, 2), &data) == 0;
    }

    ~Impl()
    {
        CloseSocket();
        if (winsockInitialized)
            WSACleanup();
    }

    void CloseSocket() noexcept
    {
        if (socket == INVALID_SOCKET)
            return;

        shutdown(socket, SD_BOTH);
        closesocket(socket);
        socket = INVALID_SOCKET;
    }

    bool SendAll(const void* data, std::size_t size)
    {
        auto* bytes = static_cast<const char*>(data);

        while (size)
        {
            const auto chunkSize =
                    static_cast<int>((std::min) (size, static_cast<std::size_t>((std::numeric_limits<int>::max)())));
            const int sent = send(socket, bytes, chunkSize, 0);
            if (sent == SOCKET_ERROR || sent == 0)
            {
                CloseSocket();
                return false;
            }

            bytes += sent;
            size -= static_cast<std::size_t>(sent);
        }

        return true;
    }

    bool ReceiveAll(void* data, std::size_t size)
    {
        auto* bytes = static_cast<char*>(data);

        while (size)
        {
            const auto chunkSize =
                    static_cast<int>((std::min) (size, static_cast<std::size_t>((std::numeric_limits<int>::max)())));
            const int received = recv(socket, bytes, chunkSize, 0);
            if (received == SOCKET_ERROR || received == 0)
            {
                CloseSocket();
                return false;
            }

            bytes += received;
            size -= static_cast<std::size_t>(received);
        }

        return true;
    }

    template<typename Packet>
    bool SendPacket(const Packet& packet)
    {
        const std::uint64_t packetSize = sizeof(packet);
        return SendAll(&packetSize, sizeof(packetSize)) && SendAll(&packet, sizeof(packet));
    }

    bool ReceiveExpectedSize(std::size_t expectedSize)
    {
        std::uint64_t responseSize = 0;
        if (!ReceiveAll(&responseSize, sizeof(responseSize)))
            return false;

        if (responseSize == 0)
            return false;

        if (responseSize != expectedSize)
        {
            CloseSocket();
            return false;
        }

        return true;
    }

    bool ReadBytes(std::uint64_t processId, std::uintptr_t address, void* destination, std::size_t size)
    {
        if (socket == INVALID_SOCKET)
            return false;

        const MemoryPacket packet{Operation::Read, 0, address, processId, size};
        return SendPacket(packet) && ReceiveExpectedSize(size) && ReceiveAll(destination, size);
    }

    bool WriteBytes(std::uint64_t processId, std::uintptr_t address, const void* source, std::size_t size)
    {
        if (socket == INVALID_SOCKET)
            return false;

        const MemoryPacket packet{Operation::WriteForce, 0, address, processId, size};
        std::uint8_t status = 0;
        return SendPacket(packet) && SendAll(source, size) && ReceiveExpectedSize(sizeof(status)) &&
               ReceiveAll(&status, sizeof(status)) && status;
    }

    std::optional<std::uintptr_t> GetProcessBase(std::uint64_t processId)
    {
        if (socket == INVALID_SOCKET)
            return std::nullopt;

        const MemoryPacket packet{Operation::ProcessBase, 0, 0, processId, 0};
        std::uintptr_t baseAddress = 0;
        if (!SendPacket(packet) || !ReceiveExpectedSize(sizeof(baseAddress)) ||
            !ReceiveAll(&baseAddress, sizeof(baseAddress)) || !baseAddress)
            return std::nullopt;

        return baseAddress;
    }

    SOCKET socket{INVALID_SOCKET};
    bool winsockInitialized{};
    std::uint64_t boundProcessId{};
    mutable std::mutex mutex;
};

plato::DriverClient& plato::DriverClient::Instance()
{
    static DriverClient instance;
    return instance;
}

plato::DriverClient::DriverClient() : m_impl(std::make_unique<Impl>())
{
}

plato::DriverClient::~DriverClient() = default;

bool plato::DriverClient::Connect(std::string_view host, std::uint16_t port)
{
    std::scoped_lock lock(m_impl->mutex);
    m_impl->CloseSocket();

    if (!m_impl->winsockInitialized || host.empty())
        return false;

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    const std::string hostName(host);
    const std::string service = std::to_string(port);
    addrinfo* addresses = nullptr;
    if (getaddrinfo(hostName.c_str(), service.c_str(), &hints, &addresses) != 0)
        return false;

    for (auto* address = addresses; address; address = address->ai_next)
    {
        SOCKET candidate = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (candidate == INVALID_SOCKET)
            continue;

        constexpr int enabled = 1;
        if (setsockopt(candidate, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char*>(&enabled), sizeof(enabled)) ==
                    SOCKET_ERROR ||
            connect(candidate, address->ai_addr, static_cast<int>(address->ai_addrlen)) == SOCKET_ERROR)
        {
            closesocket(candidate);
            continue;
        }

        m_impl->socket = candidate;
        break;
    }

    freeaddrinfo(addresses);
    return m_impl->socket != INVALID_SOCKET;
}

void plato::DriverClient::Disconnect() noexcept
{
    std::scoped_lock lock(m_impl->mutex);
    m_impl->CloseSocket();
}

bool plato::DriverClient::IsConnected() const noexcept
{
    std::scoped_lock lock(m_impl->mutex);
    return m_impl->socket != INVALID_SOCKET;
}

bool plato::DriverClient::Bind(std::string_view processName)
{
    const std::uint64_t processId = FindProcessId(processName);

    std::scoped_lock lock(m_impl->mutex);
    m_impl->boundProcessId = processId;
    return processId != 0;
}

void plato::DriverClient::Unbind() noexcept
{
    std::scoped_lock lock(m_impl->mutex);
    m_impl->boundProcessId = 0;
}

std::optional<std::uint64_t> plato::DriverClient::BoundProcessId() const noexcept
{
    std::scoped_lock lock(m_impl->mutex);
    if (!m_impl->boundProcessId)
        return std::nullopt;

    return m_impl->boundProcessId;
}

bool plato::DriverClient::ReadBytes(std::uintptr_t address, void* destination, std::size_t size)
{
    if (!address || !destination || !size || size > kMaxTransferSize)
        return false;

    std::scoped_lock lock(m_impl->mutex);
    if (!m_impl->boundProcessId)
        return false;

    return m_impl->ReadBytes(m_impl->boundProcessId, address, destination, size);
}

bool plato::DriverClient::WriteBytes(std::uintptr_t address, const void* source, std::size_t size)
{
    if (!address || !source || !size || size > kMaxTransferSize)
        return false;

    std::scoped_lock lock(m_impl->mutex);
    if (!m_impl->boundProcessId)
        return false;

    return m_impl->WriteBytes(m_impl->boundProcessId, address, source, size);
}

std::optional<std::uintptr_t> plato::DriverClient::GetProcessBase()
{
    std::scoped_lock lock(m_impl->mutex);
    if (!m_impl->boundProcessId)
        return std::nullopt;

    return m_impl->GetProcessBase(m_impl->boundProcessId);
}

bool plato::DriverClient::ReadBytes(std::uint64_t processId, std::uintptr_t address, void* destination,
                                    std::size_t size)
{
    if (!processId || !address || !destination || !size || size > kMaxTransferSize)
        return false;

    std::scoped_lock lock(m_impl->mutex);
    return m_impl->ReadBytes(processId, address, destination, size);
}

bool plato::DriverClient::WriteBytes(std::uint64_t processId, std::uintptr_t address, const void* source,
                                     std::size_t size)
{
    if (!processId || !address || !source || !size || size > kMaxTransferSize)
        return false;

    std::scoped_lock lock(m_impl->mutex);
    return m_impl->WriteBytes(processId, address, source, size);
}

std::optional<std::uintptr_t> plato::DriverClient::GetProcessBase(std::uint64_t processId)
{
    if (!processId)
        return std::nullopt;

    std::scoped_lock lock(m_impl->mutex);
    return m_impl->GetProcessBase(processId);
}

bool plato::DriverClient::MoveMouseRelative(std::int32_t x, std::int32_t y)
{
    std::scoped_lock lock(m_impl->mutex);
    if (m_impl->socket == INVALID_SOCKET)
        return false;

    const MouseMovePacket packet{Operation::MoveMouseRelative, x, y};
    std::uint8_t status = 0;
    return m_impl->SendPacket(packet) && m_impl->ReceiveExpectedSize(sizeof(status)) &&
           m_impl->ReceiveAll(&status, sizeof(status)) && status;
}
