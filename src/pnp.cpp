/* Copyright (c) Mark Harmstone 2019
 *
 * This file is part of WinMD.
 *
 * WinMD is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public Licence as published by
 * the Free Software Foundation, either version 3 of the Licence, or
 * (at your option) any later version.
 *
 * WinBtrfs is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public Licence for more details.
 *
 * You should have received a copy of the GNU Lesser General Public Licence
 * along with WinMD.  If not, see <http://www.gnu.org/licenses/>. */

#include "winmd.h"
#include <ntddstor.h>

bool no_pnp = false;

extern ERESOURCE dev_lock;
extern LIST_ENTRY dev_list;
extern PDRIVER_OBJECT drvobj;

NTSTATUS drv_pnp(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    auto dev = (device*)DeviceObject->DeviceExtension;

    bool no_complete = false;

    Status = dev->pnp(Irp, &no_complete);

    if (!no_complete) {
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    FsRtlExitFileSystem();

    return Status;
}

NTSTATUS set_pdo::query_hardware_ids(PIRP Irp) {
    static const char16_t ids[] = u"WinMDVolume\0";

    auto out = (char16_t*)ExAllocatePoolWithTag(PagedPool, sizeof(ids), ALLOC_TAG);
    if (!out) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(out, ids, sizeof(ids));

    Irp->IoStatus.Information = (ULONG_PTR)out;

    return STATUS_SUCCESS;
}

static char16_t hex_digit(uint8_t c) {
    if (c < 10)
        return c + u'0';

    return c - 10 + u'a';
}

NTSTATUS set_pdo::query_device_ids(PIRP Irp) {
    char16_t name[100];

    static const char16_t pref[] = u"WinMD\\";

    RtlCopyMemory(name, pref, sizeof(pref) - sizeof(char16_t));

    char16_t* noff = &name[(sizeof(pref) / sizeof(char16_t)) - 1];
    for (unsigned int i = 0; i < 16; i++) {
        *noff = hex_digit(array_info.set_uuid[i] >> 4); noff++;
        *noff = hex_digit(array_info.set_uuid[i] & 0xf); noff++;

        if (i == 3 || i == 5 || i == 7 || i == 9) {
            *noff = '-';
            noff++;
        }
    }
    *noff = 0;

    auto out = (char16_t*)ExAllocatePoolWithTag(PagedPool, sizeof(pref) + (36 * sizeof(char16_t)), ALLOC_TAG);
    if (!out) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(out, name, sizeof(pref) + (36 * sizeof(char16_t)));

    Irp->IoStatus.Information = (ULONG_PTR)out;

    return STATUS_SUCCESS;
}

NTSTATUS set_pdo::pnp(PIRP Irp, bool*) {
    TRACE("(%p, %p)\n", this, Irp);

    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);

    TRACE("PNP message %x\n", IrpSp->MinorFunction);

    switch (IrpSp->MinorFunction) {
        case IRP_MN_SURPRISE_REMOVAL:
        case IRP_MN_CANCEL_REMOVE_DEVICE:
        case IRP_MN_CANCEL_STOP_DEVICE:
        case IRP_MN_REMOVE_DEVICE:
            return STATUS_SUCCESS;

        case IRP_MN_QUERY_ID:
            switch (IrpSp->Parameters.QueryId.IdType) {
                case BusQueryHardwareIDs:
                    return query_hardware_ids(Irp);

                case BusQueryDeviceID:
                    return query_device_ids(Irp);

                default:
                    return Irp->IoStatus.Status;
            }

    }

    return Irp->IoStatus.Status;
}

NTSTATUS device::pnp(PIRP Irp, bool*) {
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);

    switch (IrpSp->MinorFunction) {
        case IRP_MN_SURPRISE_REMOVAL:
        case IRP_MN_CANCEL_REMOVE_DEVICE:
        case IRP_MN_CANCEL_STOP_DEVICE:
        case IRP_MN_REMOVE_DEVICE:
            return STATUS_SUCCESS;
    }

    return Irp->IoStatus.Status;
}

NTSTATUS control_device::query_capabilities(PIRP Irp) {
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);
    auto dc = IrpSp->Parameters.DeviceCapabilities.Capabilities;

    dc->UniqueID = true;
    dc->SilentInstall = true;

    return STATUS_SUCCESS;
}

NTSTATUS control_device::query_hardware_ids(PIRP Irp) {
    static const char16_t ids[] = u"ROOT\\winmd\0";

    auto out = (char16_t*)ExAllocatePoolWithTag(PagedPool, sizeof(ids), ALLOC_TAG);
    if (!out) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(out, ids, sizeof(ids));

    Irp->IoStatus.Information = (ULONG_PTR)out;

    return STATUS_SUCCESS;
}

NTSTATUS control_device::query_device_relations(PIRP Irp) {
    shared_eresource lock(&dev_lock);

    unsigned int num_children = 0;

    {
        LIST_ENTRY* le = dev_list.Flink;

        while (le != &dev_list) {
            num_children++;

            le = le->Flink;
        }
    }

    ULONG drsize = offsetof(DEVICE_RELATIONS, Objects[0]) + (num_children * sizeof(PDEVICE_OBJECT));
    auto dr = (DEVICE_RELATIONS*)ExAllocatePoolWithTag(PagedPool, drsize, ALLOC_TAG);

    if (!dr) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    dr->Count = num_children;

    {
        unsigned int i = 0;
        LIST_ENTRY* le = dev_list.Flink;

        while (le != &dev_list) {
            auto sd = CONTAINING_RECORD(le, set_pdo, list_entry);

            ObReferenceObject(sd->pdo);
            dr->Objects[i] = sd->pdo;
            i++;

            le = le->Flink;
        }
    }

    Irp->IoStatus.Information = (ULONG_PTR)dr;

    return STATUS_SUCCESS;
}

NTSTATUS control_device::pnp(PIRP Irp, bool* no_complete) {
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);

    TRACE("(%p, %p)\n", this, Irp);
    TRACE("IrpSp->MinorFunction = %x\n", IrpSp->MinorFunction);

    switch (IrpSp->MinorFunction) {
        case IRP_MN_QUERY_CAPABILITIES:
            Irp->IoStatus.Status = query_capabilities(Irp);
            break;

        case IRP_MN_QUERY_DEVICE_RELATIONS:
            if (IrpSp->Parameters.QueryDeviceRelations.Type != BusRelations || no_pnp)
                break;

            Irp->IoStatus.Status = query_device_relations(Irp);
            break;

        case IRP_MN_QUERY_ID:
        {
            if (IrpSp->Parameters.QueryId.IdType != BusQueryHardwareIDs)
                break;

            Irp->IoStatus.Status = query_hardware_ids(Irp);
            break;
        }

        case IRP_MN_START_DEVICE:
        case IRP_MN_CANCEL_REMOVE_DEVICE:
        case IRP_MN_SURPRISE_REMOVAL:
        case IRP_MN_REMOVE_DEVICE:
        case IRP_MN_QUERY_PNP_DEVICE_STATE:
            Irp->IoStatus.Status = STATUS_SUCCESS;
            break;

        case IRP_MN_QUERY_REMOVE_DEVICE:
            Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            break;
    }

    if (!NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Status != STATUS_NOT_SUPPORTED)
        return Irp->IoStatus.Status;

    *no_complete = true;

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(attached_device, Irp);
}

NTSTATUS set_device::pnp(PIRP Irp, bool* no_complete) {
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);

    TRACE("(%p, %p)\n", this, Irp);

    TRACE("PNP message %x\n", IrpSp->MinorFunction);

    switch (IrpSp->MinorFunction) {
        case IRP_MN_START_DEVICE:
        case IRP_MN_CANCEL_REMOVE_DEVICE:
        case IRP_MN_REMOVE_DEVICE:
        case IRP_MN_QUERY_PNP_DEVICE_STATE:
            Irp->IoStatus.Status = STATUS_SUCCESS;
            break;

        case IRP_MN_QUERY_REMOVE_DEVICE:
            Irp->IoStatus.Status = STATUS_UNSUCCESSFUL;
            break;

        case IRP_MN_SURPRISE_REMOVAL:
            if (open_count == 0) {
                PDEVICE_OBJECT devobj = this->devobj;

                IoDetachDevice(attached_device);

                this->set_device::~set_device();
                IoDeleteDevice(devobj);
            }

            Irp->IoStatus.Status = STATUS_SUCCESS;

            break;
    }

    if (!NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Status != STATUS_NOT_SUPPORTED)
        return Irp->IoStatus.Status;

    *no_complete = true;

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(attached_device, Irp);
}

NTSTATUS set_pdo::AddDevice() {
    NTSTATUS Status;
    UNICODE_STRING volname;
    PDEVICE_OBJECT voldev;
    set_device* sd;

    exclusive_eresource l(&lock);

    if (dev) {
        ERR("AddDevice called for already-created device\n");
        return STATUS_INTERNAL_ERROR;
    }

    volname.Length = volname.MaximumLength = sizeof(device_prefix) + (36 * sizeof(char16_t));

    volname.Buffer = (WCHAR*)ExAllocatePoolWithTag(NonPagedPool, volname.Length, ALLOC_TAG);
    if (!volname.Buffer) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(volname.Buffer, device_prefix, sizeof(device_prefix) - sizeof(char16_t));

    auto p = &volname.Buffer[(sizeof(device_prefix) / sizeof(char16_t)) - 1];

    for (uint8_t i = 0; i < 16; i++) {
        *p = hex_digit((array_info.set_uuid[i] & 0xf0) >> 4); p++;
        *p = hex_digit(array_info.set_uuid[i] & 0xf); p++;

        if (i == 3 || i == 5 || i == 7 || i == 9) {
            *p = u'-'; p++;
        }
    }

    *p = u'}';

    Status = IoCreateDevice(drvobj, sizeof(set_device), &volname, FILE_DEVICE_DISK,
                            RtlIsNtDdiVersionAvailable(NTDDI_WIN8) ? FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL : 0, false, &voldev);

    ExFreePool(volname.Buffer);

    if (!NT_SUCCESS(Status)) {
        ERR("IoCreateDevice returned %08x\n", Status);
        return Status;
    }

    voldev->Flags |= DO_DIRECT_IO;

    new (voldev->DeviceExtension) set_device(this, voldev);

    sd = (set_device*)voldev->DeviceExtension;

    Status = IoRegisterDeviceInterface(pdo, &GUID_DEVINTERFACE_VOLUME, nullptr, &bus_name);
    if (!NT_SUCCESS(Status))
        WARN("IoRegisterDeviceInterface returned %08x\n", Status);

    sd->attached_device = IoAttachDeviceToDeviceStack(voldev, pdo);

    voldev->StackSize = stack_size;
    voldev->SectorSize = dev_sector_size;

    dev = sd;

    voldev->Flags &= ~DO_DEVICE_INITIALIZING;

    Status = IoSetDeviceInterfaceState(&bus_name, true);
    if (!NT_SUCCESS(Status))
        WARN("IoSetDeviceInterfaceState returned %08x\n", Status);

    return STATUS_SUCCESS;
}

NTSTATUS __stdcall AddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject) {
    TRACE("(%p, %p)\n", DriverObject, PhysicalDeviceObject);

    set_pdo* sd = nullptr;

    {
        shared_eresource lock(&dev_lock);

        LIST_ENTRY* le = dev_list.Flink;

        while (le != &dev_list) {
            auto sd2 = CONTAINING_RECORD(le, set_pdo, list_entry);

            if (sd2->pdo == PhysicalDeviceObject) {
                sd = sd2;
                break;
            }

            le = le->Flink;
        }
    }

    if (!sd) {
        WARN("unrecognized PDO %p\n", PhysicalDeviceObject);
        return STATUS_NOT_SUPPORTED;
    }

    return sd->AddDevice();
}
