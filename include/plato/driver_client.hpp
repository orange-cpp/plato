#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <type_traits>

namespace plato
{
    class DriverClient final
    {
    public:
        static DriverClient& Instance();

        DriverClient(const DriverClient&) = delete;
        DriverClient& operator=(const DriverClient&) = delete;
        DriverClient(DriverClient&&) = delete;
        DriverClient& operator=(DriverClient&&) = delete;

        ~DriverClient();

        [[nodiscard]] bool Connect(std::string_view host = "127.0.0.1", std::uint16_t port = 7653);
        void Disconnect() noexcept;
        [[nodiscard]] bool IsConnected() const noexcept;

        [[nodiscard]] bool Bind(std::string_view processName);
        void Unbind() noexcept;
        [[nodiscard]] std::optional<std::uint64_t> BoundProcessId() const noexcept;

        [[nodiscard]] bool ReadBytes(std::uintptr_t address, void* destination, std::size_t size);
        [[nodiscard]] bool WriteBytes(std::uintptr_t address, const void* source, std::size_t size);
        [[nodiscard]] std::optional<std::uintptr_t> GetProcessBase();

        [[nodiscard]] bool ReadBytes(std::uint64_t processId, std::uintptr_t address, void* destination,
                                     std::size_t size);
        [[nodiscard]] bool WriteBytes(std::uint64_t processId, std::uintptr_t address, const void* source,
                                      std::size_t size);
        [[nodiscard]] std::optional<std::uintptr_t> GetProcessBase(std::uint64_t processId);
        [[nodiscard]] bool MoveMouseRelative(std::int32_t x, std::int32_t y);

        template<typename T>
            requires(std::is_trivially_copyable_v<T> && std::is_default_constructible_v<T> &&
                     std::is_move_constructible_v<T>)
        [[nodiscard]] std::optional<T> Read(std::uintptr_t address)
        {
            T value{};
            if (!ReadBytes(address, &value, sizeof(value)))
                return std::nullopt;

            return value;
        }

        template<typename T>
            requires(std::is_trivially_copyable_v<T> && std::is_default_constructible_v<T> &&
                     std::is_move_constructible_v<T>)
        [[nodiscard]] std::optional<T> Read(std::uint64_t processId, std::uintptr_t address)
        {
            T value{};
            if (!ReadBytes(processId, address, &value, sizeof(value)))
                return std::nullopt;

            return value;
        }

        template<typename T>
            requires std::is_trivially_copyable_v<T>
        [[nodiscard]] bool Write(std::uintptr_t address, const T& value)
        {
            return WriteBytes(address, &value, sizeof(value));
        }

        template<typename T>
            requires std::is_trivially_copyable_v<T>
        [[nodiscard]] bool Write(std::uint64_t processId, std::uintptr_t address, const T& value)
        {
            return WriteBytes(processId, address, &value, sizeof(value));
        }

    private:
        DriverClient();

        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };
} // namespace plato
