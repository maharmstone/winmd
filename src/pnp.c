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
extern bool is_windows_8;

static NTSTATUS set_query_hardware_ids(PIRP Irp) {
    static const char16_t ids[] = u"WinMDVolume\0";

    char16_t* out = ExAllocatePoolWithTag(PagedPool, sizeof(ids), ALLOC_TAG);
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

static NTSTATUS query_device_ids(mdraid_array_info* array_info, PIRP Irp) {
    char16_t name[100];

    static const char16_t pref[] = u"WinMD\\";

    RtlCopyMemory(name, pref, sizeof(pref) - sizeof(char16_t));

    char16_t* noff = &name[(sizeof(pref) / sizeof(char16_t)) - 1];
    for (unsigned int i = 0; i < 16; i++) {
        *noff = hex_digit(array_info->set_uuid[i] >> 4); noff++;
        *noff = hex_digit(array_info->set_uuid[i] & 0xf); noff++;

        if (i == 3 || i == 5 || i == 7 || i == 9) {
            *noff = '-';
            noff++;
        }
    }
    *noff = 0;

    char16_t* out = ExAllocatePoolWithTag(PagedPool, sizeof(pref) + (36 * sizeof(char16_t)), ALLOC_TAG);
    if (!out) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(out, name, sizeof(pref) + (36 * sizeof(char16_t)));

    Irp->IoStatus.Information = (ULONG_PTR)out;

    return STATUS_SUCCESS;
}

static NTSTATUS pdo_pnp(set_pdo* pdo, PIRP Irp) {
    TRACE("(%p, %p)\n", pdo, Irp);

    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

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
                    return set_query_hardware_ids(Irp);

                case BusQueryDeviceID:
                    return query_device_ids(&pdo->array_info, Irp);

                default:
                    return Irp->IoStatus.Status;
            }

    }

    return Irp->IoStatus.Status;
}

static NTSTATUS query_capabilities(PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PDEVICE_CAPABILITIES dc = IrpSp->Parameters.DeviceCapabilities.Capabilities;

    dc->UniqueID = true;
    dc->SilentInstall = true;

    return STATUS_SUCCESS;
}

static NTSTATUS query_hardware_ids(PIRP Irp) {
    static const char16_t ids[] = u"ROOT\\winmd\0";

    char16_t* out = ExAllocatePoolWithTag(PagedPool, sizeof(ids), ALLOC_TAG);
    if (!out) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlCopyMemory(out, ids, sizeof(ids));

    Irp->IoStatus.Information = (ULONG_PTR)out;

    return STATUS_SUCCESS;
}

static NTSTATUS query_device_relations(PIRP Irp) {
    ExAcquireResourceSharedLite(&dev_lock, true);

    unsigned int num_children = 0;

    {
        LIST_ENTRY* le = dev_list.Flink;

        while (le != &dev_list) {
            num_children++;

            le = le->Flink;
        }
    }

    ULONG drsize = offsetof(DEVICE_RELATIONS, Objects[0]) + (num_children * sizeof(PDEVICE_OBJECT));
    DEVICE_RELATIONS* dr = ExAllocatePoolWithTag(PagedPool, drsize, ALLOC_TAG);

    if (!dr) {
        ERR("out of memory\n");
        ExReleaseResourceLite(&dev_lock);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    dr->Count = num_children;

    {
        unsigned int i = 0;
        LIST_ENTRY* le = dev_list.Flink;

        while (le != &dev_list) {
            set_pdo* sd = CONTAINING_RECORD(le, set_pdo, list_entry);

            ObReferenceObject(sd->pdo);
            dr->Objects[i] = sd->pdo;
            i++;

            le = le->Flink;
        }
    }

    Irp->IoStatus.Information = (ULONG_PTR)dr;

    ExReleaseResourceLite(&dev_lock);

    return STATUS_SUCCESS;
}

static NTSTATUS control_pnp(control_device* control, PIRP Irp, bool* no_complete) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    TRACE("(%p, %p)\n", control, Irp);
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
    return IoCallDriver(control->attached_device, Irp);
}

static NTSTATUS set_pnp(set_device* set, PIRP Irp, bool* no_complete) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    TRACE("(%p, %p)\n", set, Irp);

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
            if (set->open_count == 0) {
                PDEVICE_OBJECT devobj = set->devobj;

                IoDetachDevice(set->attached_device);

                ExDeleteResourceLite(&set->lock);
                IoDeleteDevice(devobj);
            }

            Irp->IoStatus.Status = STATUS_SUCCESS;

            break;
    }

    if (!NT_SUCCESS(Irp->IoStatus.Status) && Irp->IoStatus.Status != STATUS_NOT_SUPPORTED)
        return Irp->IoStatus.Status;

    *no_complete = true;

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(set->attached_device, Irp);
}

NTSTATUS drv_pnp(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    bool no_complete = false;

    switch (*(enum device_type*)DeviceObject->DeviceExtension) {
        case device_type_control:
            Status = control_pnp((control_device*)(DeviceObject->DeviceExtension), Irp, &no_complete);
            break;

        case device_type_set:
            Status = set_pnp((set_device*)(DeviceObject->DeviceExtension), Irp, &no_complete);
            break;

        case device_type_pdo:
            Status = pdo_pnp((set_pdo*)(DeviceObject->DeviceExtension), Irp);
            break;

        default: {
            PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

            switch (IrpSp->MinorFunction) {
                case IRP_MN_SURPRISE_REMOVAL:
                case IRP_MN_CANCEL_REMOVE_DEVICE:
                case IRP_MN_CANCEL_STOP_DEVICE:
                case IRP_MN_REMOVE_DEVICE:
                    Status = STATUS_SUCCESS;
                    break;

                default:
                    Status = Irp->IoStatus.Status;
            }
        }
    }

    if (!no_complete) {
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    if (top_level)
        IoSetTopLevelIrp(NULL);

    FsRtlExitFileSystem();

    return Status;
}

static NTSTATUS add_set_device(set_pdo* pdo) {
    NTSTATUS Status;
    UNICODE_STRING volname;
    PDEVICE_OBJECT voldev;
    set_device* sd;

    ExAcquireResourceExclusiveLite(&pdo->lock, true);

    if (pdo->dev) {
        ERR("AddDevice called for already-created device\n");
        Status = STATUS_INTERNAL_ERROR;
        goto end;
    }

    volname.Length = volname.MaximumLength = sizeof(device_prefix) + (36 * sizeof(char16_t));

    volname.Buffer = ExAllocatePoolWithTag(NonPagedPool, volname.Length, ALLOC_TAG);
    if (!volname.Buffer) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    RtlCopyMemory(volname.Buffer, device_prefix, sizeof(device_prefix) - sizeof(char16_t));

    {
        WCHAR* p = &volname.Buffer[(sizeof(device_prefix) / sizeof(char16_t)) - 1];

        for (uint8_t i = 0; i < 16; i++) {
            *p = hex_digit((pdo->array_info.set_uuid[i] & 0xf0) >> 4); p++;
            *p = hex_digit(pdo->array_info.set_uuid[i] & 0xf); p++;

            if (i == 3 || i == 5 || i == 7 || i == 9) {
                *p = u'-'; p++;
            }
        }

        *p = u'}';
    }

    Status = IoCreateDevice(drvobj, sizeof(set_device), &volname, FILE_DEVICE_DISK,
                            is_windows_8 ? FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL : 0, false, &voldev);

    ExFreePool(volname.Buffer);

    if (!NT_SUCCESS(Status)) {
        ERR("IoCreateDevice returned %08x\n", Status);
        goto end;
    }

    voldev->Flags |= DO_DIRECT_IO;

    sd = (set_device*)voldev->DeviceExtension;
    sd->type = device_type_set;
    sd->pdo = pdo;
    sd->devobj = voldev;
    sd->open_count = 0;

    ExInitializeResourceLite(&sd->lock);

    Status = IoRegisterDeviceInterface(pdo->pdo, &GUID_DEVINTERFACE_VOLUME, NULL, &pdo->bus_name);
    if (!NT_SUCCESS(Status))
        WARN("IoRegisterDeviceInterface returned %08x\n", Status);

    sd->attached_device = IoAttachDeviceToDeviceStack(voldev, pdo->pdo);

    voldev->StackSize = pdo->stack_size;
    voldev->SectorSize = pdo->dev_sector_size;

    pdo->dev = sd;

    voldev->Flags &= ~DO_DEVICE_INITIALIZING;

    Status = IoSetDeviceInterfaceState(&pdo->bus_name, true);
    if (!NT_SUCCESS(Status))
        WARN("IoSetDeviceInterfaceState returned %08x\n", Status);

    Status = STATUS_SUCCESS;

end:
    ExReleaseResourceLite(&pdo->lock);

    return Status;
}

NTSTATUS __stdcall AddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject) {
    TRACE("(%p, %p)\n", DriverObject, PhysicalDeviceObject);

    set_pdo* sd = NULL;

    ExAcquireResourceSharedLite(&dev_lock, true);

    LIST_ENTRY* le = dev_list.Flink;

    while (le != &dev_list) {
        set_pdo* sd2 = CONTAINING_RECORD(le, set_pdo, list_entry);

        if (sd2->pdo == PhysicalDeviceObject) {
            sd = sd2;
            break;
        }

        le = le->Flink;
    }

    ExReleaseResourceLite(&dev_lock);

    if (!sd) {
        WARN("unrecognized PDO %p\n", PhysicalDeviceObject);
        return STATUS_NOT_SUPPORTED;
    }

    return add_set_device(sd);
}
