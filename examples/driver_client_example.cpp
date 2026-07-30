#include "plato/driver_client.hpp"

#include <cstdint>
#include <cstdio>
#include <print>

int main()
{
    auto& driver = plato::DriverClient::Instance();

    if (!driver.Connect() || !driver.Bind("notepad.exe"))
    {
        std::println(stderr, "Failed to connect to the driver or bind to notepad.exe.");
        return 1;
    }

    const auto pid = driver.BoundProcessId();
    const auto base = driver.GetProcessBase();
    if (!pid || !base)
    {
        std::println(stderr, "Failed to obtain the bound process information.");
        return 1;
    }

    std::println("PID: {}", *pid);
    std::println("Base: 0x{:X}", *base);

    constexpr std::uintptr_t address = 0x29CC0406EA8;
    const auto value = driver.Read<std::int32_t>(address);
    if (!value)
    {
        std::println(stderr, "Failed to read int32 at 0x{:X}.", address);
        return 1;
    }

    std::println("Read int32: {}", *value);

    if (!driver.Write<std::int32_t>(address, 42))
    {
        std::println(stderr, "Failed to write int32 at 0x{:X}.", address);
        return 1;
    }

    std::println("Wrote int32: 42");
    return 0;
}
