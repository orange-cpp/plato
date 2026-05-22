#include "mouse.h"

#include <cstdint>

extern "C"
{
    extern POBJECT_TYPE* IoDriverObjectType;

    NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes,
                                            PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess,
                                            POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode,
                                            PVOID ParseContext, PVOID* Object);
}

namespace
{
    using MouseClassServiceCallback = VOID (*)(PDEVICE_OBJECT DeviceObject, PMOUSE_INPUT_DATA InputDataStart,
                                               PMOUSE_INPUT_DATA InputDataEnd, PULONG InputDataConsumed);

    struct MouseContext
    {
        PDEVICE_OBJECT classDevice = nullptr;
        MouseClassServiceCallback serviceCallback = nullptr;
    };

    MouseContext g_mouse;

    bool IsInDriverImage(PDRIVER_OBJECT driverObject, uintptr_t address)
    {
        const auto start = reinterpret_cast<uintptr_t>(driverObject->DriverStart);
        const auto end = start + driverObject->DriverSize;
        return address >= start && address < end;
    }

    bool FindMouseClassServiceCallback(PDRIVER_OBJECT classDriverObject, PDRIVER_OBJECT hidDriverObject)
    {
        for (auto hidDevice = hidDriverObject->DeviceObject; hidDevice && !g_mouse.serviceCallback;
             hidDevice = hidDevice->NextDevice)
        {
            if (!hidDevice->DeviceExtension || hidDevice->Size <= sizeof(DEVICE_OBJECT))
                continue;

            const auto extension = static_cast<uintptr_t*>(hidDevice->DeviceExtension);
            const auto extensionSize = (hidDevice->Size - sizeof(DEVICE_OBJECT)) / sizeof(uintptr_t);

            for (auto classDevice = classDriverObject->DeviceObject; classDevice && !g_mouse.serviceCallback;
                 classDevice = classDevice->NextDevice)
            {
                const auto classDeviceAddress = reinterpret_cast<uintptr_t>(classDevice);

                for (size_t i = 0; i + 1 < extensionSize; ++i)
                {
                    if (extension[i] != classDeviceAddress || !IsInDriverImage(classDriverObject, extension[i + 1]))
                        continue;

                    g_mouse.classDevice = classDevice;
                    g_mouse.serviceCallback = reinterpret_cast<MouseClassServiceCallback>(extension[i + 1]);
                    ObReferenceObject(g_mouse.classDevice);
                    return true;
                }
            }
        }

        return false;
    }

    bool InitializeMouse()
    {
        if (g_mouse.classDevice && g_mouse.serviceCallback)
            return true;

        UNICODE_STRING classDriverName{};
        UNICODE_STRING hidDriverName{};
        RtlInitUnicodeString(&classDriverName, L"\\Driver\\MouClass");
        RtlInitUnicodeString(&hidDriverName, L"\\Driver\\MouHID");

        PDRIVER_OBJECT classDriverObject = nullptr;
        PDRIVER_OBJECT hidDriverObject = nullptr;

        auto status = ObReferenceObjectByName(&classDriverName, OBJ_CASE_INSENSITIVE, nullptr, 0,
                                              *IoDriverObjectType, KernelMode, nullptr,
                                              reinterpret_cast<PVOID*>(&classDriverObject));
        if (!NT_SUCCESS(status))
            return false;

        status = ObReferenceObjectByName(&hidDriverName, OBJ_CASE_INSENSITIVE, nullptr, 0,
                                         *IoDriverObjectType, KernelMode, nullptr,
                                         reinterpret_cast<PVOID*>(&hidDriverObject));
        if (!NT_SUCCESS(status))
        {
            ObDereferenceObject(classDriverObject);
            return false;
        }

        const bool found = FindMouseClassServiceCallback(classDriverObject, hidDriverObject);

        ObDereferenceObject(hidDriverObject);
        ObDereferenceObject(classDriverObject);
        return found;
    }
}

bool mouse::MoveRelative(LONG x, LONG y)
{
    if (!x && !y)
        return true;

    if (!InitializeMouse())
        return false;

    const KIRQL currentIrql = KeGetCurrentIrql();
    if (currentIrql > DISPATCH_LEVEL)
        return false;

    MOUSE_INPUT_DATA input{};
    input.Flags = MOUSE_MOVE_RELATIVE;
    input.LastX = x;
    input.LastY = y;

    ULONG consumed = 0;
    KIRQL oldIrql = currentIrql;
    if (currentIrql < DISPATCH_LEVEL)
        KeRaiseIrql(DISPATCH_LEVEL, &oldIrql);

    g_mouse.serviceCallback(g_mouse.classDevice, &input, &input + 1, &consumed);

    if (currentIrql < DISPATCH_LEVEL)
        KeLowerIrql(oldIrql);

    return consumed == 1;
}
