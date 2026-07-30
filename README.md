# plato

`plato` is a Windows x64 kernel-driver experiment with a C++23 user-mode client library. The driver exposes process
memory, process image-base, and relative mouse operations through a small TCP protocol.

> [!WARNING]
> The current driver binds TCP port `7653` to all IPv4 interfaces and does not authenticate clients. A reachable client
> can request privileged process-memory operations and mouse input. Use this project only in an isolated development
> environment; do not expose the port to an untrusted network.

## Components

- `plato.sys` — KMDF driver and TCP command server.
- `plato_client.lib` — thread-safe C++23 client library using a singleton and PImpl.
- `plato_client_example.exe` — minimal client-library example.
- `scripts/` — Python utilities for manual integration testing.
- `extlibs/ksocket` — WSK socket wrapper included as a Git submodule.

The client uses one persistent socket with `TCP_NODELAY`. Connection state, process binding, and complete
request/response exchanges are protected by one mutex, preventing concurrent requests from interleaving on the wire.

## Requirements

- Windows x64
- Visual Studio with the MSVC C++ toolchain
- Windows Driver Kit with KMDF 1.15
- CMake 3.30 or newer
- Ninja
- Python 3 for the optional scripts

Initialize the Git submodule after cloning:

```powershell
git submodule update --init --recursive
```

Run the build from a Visual Studio Developer PowerShell or another environment where MSVC, the Windows SDK, and the WDK
are configured.

## Building

Debug:

```powershell
cmake --preset windows-debug
cmake --build cmake-build/build/windows-debug --parallel
```

Release:

```powershell
cmake --preset windows-release
cmake --build cmake-build/build/windows-release --parallel
```

Generated artifacts are placed under `out/Debug` or `out/Release`:

- `plato.sys`
- `plato_client.lib`
- `plato_client_example.exe`

Building does not load or start the driver. Use an appropriate driver-development and test-signing environment. The
current driver does not implement a controlled unload path.

## CI/CD

GitHub Actions CI runs for pushes to `main`, pull requests, and manual dispatches. It builds Debug and Release on the
`windows-2022` runner and publishes the driver, client library, and example as separate workflow artifacts.

Pushing a version tag builds the Release configuration and publishes the three binaries to the corresponding GitHub
Release:

```powershell
git tag v1.0.0
git push origin v1.0.0
```

The produced driver is unsigned; the workflows do not load or deploy it.

Workflow definitions are in `.github/workflows/ci.yml` and `.github/workflows/release.yml`.

## C++ client library

Include the public header and link the CMake target:

```cmake
target_link_libraries(your_application PRIVATE plato_client)
```

```cpp
#include <plato/driver_client.hpp>

#include <cstdint>
#include <print>

int main()
{
    auto& driver = plato::DriverClient::Instance();

    if (!driver.Connect() || !driver.Bind("notepad.exe"))
        return 1;

    const auto pid = driver.BoundProcessId();
    const auto base = driver.GetProcessBase();
    if (!pid || !base)
        return 1;

    std::println("PID: {}", *pid);
    std::println("Base: 0x{:X}", *base);

    constexpr std::uintptr_t address = 0x12345678; // Replace with a valid address in the bound process.

    if (const auto value = driver.Read<std::int32_t>(address))
        std::println("Value: {}", *value);

    if (!driver.Write<std::int32_t>(address, 42))
        return 1;

    return 0;
}
```

`Bind` performs a case-insensitive process-name lookup, accepts names with or without `.exe`, and stores the first
matching PID in the singleton. A failed bind clears the previous binding.

Bound-process operations:

```cpp
driver.Read<T>(address);
driver.Write<T>(address, value);
driver.GetProcessBase();
```

Explicit-PID overloads remain available:

```cpp
driver.Read<T>(pid, address);
driver.Write<T>(pid, address, value);
driver.GetProcessBase(pid);
```

`T` must be trivially copyable. Raw transfers are available through `ReadBytes` and `WriteBytes`, and each transfer is
limited to 1 MiB to match the driver.

Additional connection and binding methods:

```cpp
driver.Connect("127.0.0.1", 7653);
driver.Disconnect();
driver.IsConnected();

driver.Bind("process.exe");
driver.Unbind();
driver.BoundProcessId();

driver.MoveMouseRelative(100, 0);
```

## Example executable

The example source is in `examples/driver_client_example.cpp`. Before running it, replace the placeholder address
`0x12345678` with a valid address in the selected process.

```powershell
.\out\Debug\plato_client_example.exe
```

The example performs a real driver-backed write. Do not run it against a process or address you do not intend to
modify.

## Protocol summary

The current protocol is designed for the x64 Windows builds in this repository. Values use the host's little-endian
representation.

| Operation | Value | Request |
| --- | ---: | --- |
| Read memory | `0` | PID, address, size |
| Force-write memory | `1` | PID, address, size, followed by bytes |
| Process base | `2` | PID |
| Relative mouse move | `3` | Signed X and Y deltas |

Each request starts with a 64-bit packet-size field followed by the operation packet. Each response starts with a
64-bit response-size field followed by the response bytes.

## Python integration scripts

- `test_memory_target.py` creates a user-mode buffer for memory testing.
- `test_memory_rw.py` reads and writes that buffer through the driver.
- `test_mouse_move.py` sends a relative mouse movement and optionally reverses it.
- `inspect_process_pe.py` inspects and modifies PE-header data through the driver.
- `read_notepad_int32.py` reads or updates a configured Notepad address.
- `read_pointer_chain_int32.py` is an application-specific pointer-chain experiment.

These are live integration tools, not isolated unit tests. They require the driver to be running and can modify process
state or mouse input. No automated CTest suite is currently registered.

## Implementation notes

- The memory implementation validates user ranges and caps transfer sizes.
- Physical page-table discovery scans RAM and can make the first request for a process slow.
- The driver handles one connected client at a time.
- The TCP protocol has no version negotiation, encryption, or authentication.
- Process bindings can become stale if the selected process exits or its PID is reused.

## License

MIT. See [LICENSE](LICENSE).
