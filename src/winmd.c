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

#ifndef _MSC_VER
#include <initguid.h>
#include <ntddstor.h>
#undef INITGUID
#endif

#include <ntdddisk.h>
#include <ntddvol.h>

#ifdef _MSC_VER
#include <initguid.h>
#include <ntddstor.h>
#undef INITGUID
#endif

#include <wdmguid.h>
#include <mountdev.h>

#ifdef _MSC_VER
#include <intrin.h>
#endif

#include <initguid.h>

static const WCHAR device_name[] = L"\\WinMD";

DEFINE_GUID(WinMDBusInterface, 0x034d566e, 0x836b, 0x4e79, 0x96, 0x17, 0x60, 0x23, 0x58, 0x74, 0xc9, 0x08);

#ifdef _DEBUG
serial_logger* logger = NULL;
#endif
void *notification_entry = NULL, *notification_entry2 = NULL, *notification_entry3 = NULL;
PDRIVER_OBJECT drvobj = NULL;
PDEVICE_OBJECT master_devobj = NULL;
bool have_sse2 = false;
#ifdef _DEBUG
uint32_t debug_log_level = 0;
#endif

ERESOURCE dev_lock;
LIST_ENTRY dev_list;
bool is_windows_8;

extern bool no_pnp;

typedef void (*pnp_callback)(PDRIVER_OBJECT DriverObject, PUNICODE_STRING devpath);
static NTSTATUS dev_ioctl(PDEVICE_OBJECT DeviceObject, PFILE_OBJECT FileObject, ULONG ControlCode, PVOID InputBuffer,
                          ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, bool Override, IO_STATUS_BLOCK* iosb);

typedef struct {
    PDRIVER_OBJECT DriverObject;
    UNICODE_STRING name;
    pnp_callback func;
    PIO_WORKITEM work_item;
} pnp_callback_context;

static void __stdcall do_pnp_callback(PDEVICE_OBJECT, PVOID con) {
    pnp_callback_context* context = (pnp_callback_context*)con;

    context->func(context->DriverObject, &context->name);

    if (context->name.Buffer)
        ExFreePool(context->name.Buffer);

    IoFreeWorkItem(context->work_item);
}

static void enqueue_pnp_callback(PDRIVER_OBJECT DriverObject, PUNICODE_STRING name, pnp_callback func) {
    PIO_WORKITEM work_item = IoAllocateWorkItem(master_devobj);

    pnp_callback_context* context = ExAllocatePoolWithTag(PagedPool, sizeof(pnp_callback_context), ALLOC_TAG);

    if (!context) {
        ERR("out of memory\n");
        IoFreeWorkItem(work_item);
        return;
    }

    context->DriverObject = DriverObject;

    if (name->Length > 0) {
        context->name.Buffer = ExAllocatePoolWithTag(PagedPool, name->Length, ALLOC_TAG);
        if (!context->name.Buffer) {
            ERR("out of memory\n");
            ExFreePool(context);
            IoFreeWorkItem(work_item);
            return;
        }

        RtlCopyMemory(context->name.Buffer, name->Buffer, name->Length);
        context->name.Length = context->name.MaximumLength = name->Length;
    } else {
        context->name.Length = context->name.MaximumLength = 0;
        context->name.Buffer = NULL;
    }

    context->func = func;
    context->work_item = work_item;

    IoQueueWorkItem(work_item, do_pnp_callback, DelayedWorkQueue, context);
}

typedef struct {
    KEVENT Event;
    IO_STATUS_BLOCK iosb;
} read_context;

static NTSTATUS __stdcall read_completion(PDEVICE_OBJECT, PIRP Irp, PVOID conptr) {
    read_context* context = (read_context*)conptr;

    context->iosb = Irp->IoStatus;
    KeSetEvent(&context->Event, 0, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS sync_read_phys(PDEVICE_OBJECT DeviceObject, PFILE_OBJECT FileObject, uint64_t StartingOffset, uint32_t Length,
                               uint8_t* Buffer, bool override) {
    IO_STATUS_BLOCK IoStatus;
    LARGE_INTEGER Offset;
    PIRP Irp;
    PIO_STACK_LOCATION IrpSp;
    NTSTATUS Status;
    read_context context;

    RtlZeroMemory(&context, sizeof(read_context));
    KeInitializeEvent(&context.Event, NotificationEvent, FALSE);

    Offset.QuadPart = (LONGLONG)StartingOffset;

    Irp = IoAllocateIrp(DeviceObject->StackSize, FALSE);

    if (!Irp) {
        ERR("IoAllocateIrp failed\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Irp->Flags |= IRP_NOCACHE;
    IrpSp = IoGetNextIrpStackLocation(Irp);
    IrpSp->FileObject = FileObject;
    IrpSp->MajorFunction = IRP_MJ_READ;

    if (override)
        IrpSp->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

    if (DeviceObject->Flags & DO_BUFFERED_IO) {
        Irp->AssociatedIrp.SystemBuffer = ExAllocatePoolWithTag(NonPagedPool, Length, ALLOC_TAG);
        if (!Irp->AssociatedIrp.SystemBuffer) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto exit;
        }

        Irp->Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | IRP_INPUT_OPERATION;

        Irp->UserBuffer = Buffer;
    } else if (DeviceObject->Flags & DO_DIRECT_IO) {
        Irp->MdlAddress = IoAllocateMdl(Buffer, Length, FALSE, FALSE, NULL);
        if (!Irp->MdlAddress) {
            ERR("IoAllocateMdl failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto exit;
        }

        Status = STATUS_SUCCESS;

        seh_try {
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoWriteAccess);
        } seh_except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (!NT_SUCCESS(Status)) {
            ERR("MmProbeAndLockPages threw exception %08x\n", Status);
            IoFreeMdl(Irp->MdlAddress);
            goto exit;
        }
    } else
        Irp->UserBuffer = Buffer;

    IrpSp->Parameters.Read.Length = Length;
    IrpSp->Parameters.Read.ByteOffset = Offset;

    Irp->UserIosb = &IoStatus;

    Irp->UserEvent = &context.Event;

    IoSetCompletionRoutine(Irp, read_completion, &context, TRUE, TRUE, TRUE);

    Status = IoCallDriver(DeviceObject, Irp);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&context.Event, Executive, KernelMode, FALSE, NULL);
        Status = context.iosb.Status;
    }

    if (DeviceObject->Flags & DO_DIRECT_IO) {
        MmUnlockPages(Irp->MdlAddress);
        IoFreeMdl(Irp->MdlAddress);
    }

exit:
    IoFreeIrp(Irp);

    return Status;
}

static WCHAR hex_digit(uint8_t c) {
    if (c < 10)
        return c + '0';

    return c - 10 + 'a';
}

// FIXME - make sure this gets called
void unit_set_pdo(set_pdo* pdo) {
    if (pdo->child_list)
        ExFreePool(pdo->child_list);

    while (!IsListEmpty(&pdo->children)) {
        set_child* c = CONTAINING_RECORD(RemoveHeadList(&pdo->children), set_child, list_entry);

        ObDereferenceObject(c->fileobj);

        if (c->devpath.Buffer)
            ExFreePool(c->devpath.Buffer);

        ExFreePool(c);
    }

    if (pdo->bus_name.Buffer)
        ExFreePool(pdo->bus_name.Buffer);

    // FIXME - make sure partial chunks list is empty

    ExDeleteResourceLite(&pdo->lock);
    ExDeleteResourceLite(&pdo->partial_chunks_lock);
}

static void device_found(PDEVICE_OBJECT devobj, PFILE_OBJECT fileobj, PUNICODE_STRING devpath, mdraid_superblock* sb) {
    set_pdo* sd;

    set_child* c = ExAllocatePoolWithTag(NonPagedPool, sizeof(set_child), ALLOC_TAG);
    if (!c) {
        ERR("out of memory\n");
        return;
    }

    c->device = devobj;
    c->fileobj = fileobj;

    ObReferenceObject(fileobj);

    RtlCopyMemory(&c->disk_info, &sb->disk_info, sizeof(mdraid_disk_info));

    c->devpath.Length = c->devpath.MaximumLength = devpath->Length;

    if (devpath->Length > 0) {
        c->devpath.Buffer = ExAllocatePoolWithTag(NonPagedPool, c->devpath.Length, ALLOC_TAG);

        if (c->devpath.Buffer)
            RtlCopyMemory(c->devpath.Buffer, devpath->Buffer, c->devpath.Length);
        else {
            ERR("out of memory\n");

            ObDereferenceObject(c->fileobj);

            if (c->devpath.Buffer)
                ExFreePool(c->devpath.Buffer);

            ExFreePool(c);
            return;
        }
    } else
        c->devpath.Buffer = NULL;

    {
        UNICODE_STRING us;
        OBJECT_ATTRIBUTES attr;
        IO_STATUS_BLOCK iosb;
        NTSTATUS Status;
        HANDLE h;

        RtlInitUnicodeString(&us, MOUNTMGR_DEVICE_NAME);
        InitializeObjectAttributes(&attr, &us, 0, NULL, NULL);

        Status = NtOpenFile(&h, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb,
                            FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_ALERT);

        if (NT_SUCCESS(Status)) {
            char c = get_drive_letter(h, devpath);

            TRACE("get_drive_letter returned %u\n", c);

            if (c != 0) {
                NTSTATUS Status = remove_drive_letter(h, c);
                if (!NT_SUCCESS(Status))
                    ERR("remove_drive_letter returned %08x\n", Status);
            }
        }

        if (h)
            NtClose(h);
    }

    ExAcquireResourceExclusiveLite(&dev_lock, true);

    LIST_ENTRY* le = dev_list.Flink;

    while (le != &dev_list) {
        sd = CONTAINING_RECORD(le, set_pdo, list_entry);

        if (RtlCompareMemory(sd->array_info.set_uuid, sb->array_info.set_uuid, sizeof(sb->array_info.set_uuid)) == sizeof(sb->array_info.set_uuid)) {
            ExAcquireResourceExclusiveLite(&sd->lock, true);

            if (sd->array_state.events != sb->array_state.events) {
                WARN("device events count is out of sync (%llu, other device has %llu)\n", sb->array_state.events, sd->array_state.events);
                ExReleaseResourceLite(&sd->lock);
                goto fail;
            }

            InsertTailList(&sd->children, &c->list_entry);

            if (sd->stack_size <= (unsigned int)devobj->StackSize) {
                sd->stack_size = devobj->StackSize + 1;

                if (sd->dev)
                    sd->dev->devobj->StackSize = sd->stack_size;
            }

            if (sd->dev_sector_size < devobj->SectorSize) {
                sd->dev_sector_size = devobj->SectorSize;

                if (sd->dev)
                    sd->dev->devobj->SectorSize = sd->dev_sector_size;
            }

            if (sb->disk_info.dev_number < sd->array_state.max_dev && sd->roles.dev_roles[sb->disk_info.dev_number] < sd->array_info.raid_disks &&
                !sd->child_list[sd->roles.dev_roles[sb->disk_info.dev_number]]) {
                sd->found_devices++;
                sd->child_list[sd->roles.dev_roles[sb->disk_info.dev_number]] = c;

                if (sd->array_info.level == RAID_LEVEL_0 || sd->array_info.level == RAID_LEVEL_LINEAR)
                    sd->array_size += sb->disk_info.data_size * 512;

                if (sd->found_devices == sd->array_info.raid_disks)
                    sd->loaded = true;
            }

            ExReleaseResourceLite(&sd->lock);
            ExReleaseResourceLite(&dev_lock);
            return;
        }

        le = le->Flink;
    }

    if (sb->array_info.level == RAID_LEVEL_0 || sb->array_info.level == RAID_LEVEL_4 || sb->array_info.level == RAID_LEVEL_5 ||
        sb->array_info.level == RAID_LEVEL_6 || sb->array_info.level == RAID_LEVEL_10) {
        if (sb->array_info.chunksize == 0) {
            ERR("invalid value for chunk size: cannot be 0\n");
            goto fail;
        }

        if (((sb->array_info.chunksize * 512) % PAGE_SIZE) != 0) {
            ERR("invalid value for chunk size (%u): must be multiple of 4096\n", sb->array_info.chunksize * 512);
            goto fail;
        }
    }

    if (sb->array_info.level == RAID_LEVEL_10) {
        uint8_t near = sb->array_info.layout & 0xff;
        uint8_t far = (sb->array_info.layout >> 8) & 0xff;
        bool offset = sb->array_info.layout & 0x10000;

        if (near == 0 || near > sb->array_info.raid_disks) {
            ERR("invalid near value %u, expected between 1 and %u\n", sb->array_info.raid_disks);
            goto fail;
        }

        if (far == 0 || far > sb->array_info.raid_disks) {
            ERR("invalid far value %u, expected between 1 and %u\n", sb->array_info.raid_disks);
            goto fail;
        }

        if (near > 1 && far > 1) {
            ERR("at least one of near and far needs to be 1 (near = %u, far = %u)\n", near, far);
            goto fail;
        }

        if (offset && near > 1) {
            ERR("invalid value for near (%u) when offset set\n", near);
            goto fail;
        }
    }

    if (sb->array_info.level == RAID_LEVEL_0 && (sb->array_info.size * 512) % PAGE_SIZE != 0) {
        ERR("invalid value for array size (%llu): must be multiple of 4096\n");
        goto fail;
    }

    if (sb->feature_map != 0) {
        ERR("unsupported features %x\n", sb->feature_map);
        goto fail;
    }

    PDEVICE_OBJECT newdev;
    NTSTATUS Status;

    Status = IoCreateDevice(drvobj, sizeof(set_pdo), NULL, FILE_DEVICE_DISK,
                            FILE_AUTOGENERATED_DEVICE_NAME | FILE_DEVICE_SECURE_OPEN, false, &newdev);
    if (!NT_SUCCESS(Status)) {
        ERR("IoCreateDevice returned %08x\n", Status);
        goto fail;
    }

    newdev->Flags |= DO_BUS_ENUMERATED_DEVICE;

    sd = (set_pdo*)newdev->DeviceExtension;
    sd->type = device_type_pdo;
    sd->pdo = newdev;
    sd->stack_size = devobj->StackSize + 1;
    sd->dev_sector_size = devobj->SectorSize == 0 ? 512 : devobj->SectorSize;
    sd->array_size = 0;
    sd->read_device = 0;
    sd->found_devices = 0;
    sd->loaded = false;
    sd->dev = NULL;
    sd->flush_thread_handle = NULL;
    sd->readonly = false;

    ExInitializeResourceLite(&sd->lock);

    InitializeListHead(&sd->children);

    ExInitializeResourceLite(&sd->partial_chunks_lock);

    InitializeListHead(&sd->partial_chunks);

    sd->child_list = NULL;
    sd->bus_name.Buffer = NULL;

    KeInitializeEvent(&sd->flush_thread_finished, NotificationEvent, false);

    RtlCopyMemory(&sd->array_info, &sb->array_info, sizeof(sb->array_info));
    RtlCopyMemory(&sd->array_state, &sb->array_state, sizeof(sb->array_state));
    RtlCopyMemory(&sd->roles, &sb->roles, sizeof(sb->roles));

    if (sb->array_info.level == RAID_LEVEL_4 || sb->array_info.level == RAID_LEVEL_5 || sb->array_info.level == RAID_LEVEL_6) {
        Status = PsCreateSystemThread(&sd->flush_thread_handle, 0, NULL, NULL, NULL, flush_thread, sd);
        if (!NT_SUCCESS(Status)) {
            ERR("PsCreateSystemThread returned %08x\n", Status);
            IoDeleteDevice(newdev);
            goto fail;
        }
    }

    if (sd->array_info.raid_disks > 0) {
        sd->child_list = ExAllocatePoolWithTag(PagedPool, sizeof(set_child*) * sd->array_info.raid_disks, ALLOC_TAG);
        if (!sd->child_list) {
            ERR("out of memory\n");
            IoDeleteDevice(newdev);
            goto fail;
        }

        RtlZeroMemory(sd->child_list, sizeof(set_child*) * sd->array_info.raid_disks);

        if (sb->disk_info.dev_number < sd->array_state.max_dev && sd->roles.dev_roles[sb->disk_info.dev_number] < sd->array_info.raid_disks &&
            !sd->child_list[sd->roles.dev_roles[sb->disk_info.dev_number]]) {
            sd->found_devices++;
            sd->child_list[sd->roles.dev_roles[sb->disk_info.dev_number]] = c;

            if (sd->found_devices == sd->array_info.raid_disks)
                sd->loaded = true;
        }
    }

    InsertTailList(&sd->children, &c->list_entry);

    newdev->Flags &= ~DO_DEVICE_INITIALIZING;

    InsertTailList(&dev_list, &sd->list_entry);

    if (sb->array_info.level == RAID_LEVEL_0 || sd->array_info.level == RAID_LEVEL_LINEAR)
        sd->array_size = sb->disk_info.data_size * 512;
    else
        sd->array_size = sb->array_info.size * 512;

    Status = IoRegisterLastChanceShutdownNotification(newdev);
    if (!NT_SUCCESS(Status))
        ERR("IoRegisterLastChanceShutdownNotification returned %08x\n", Status);

    if (!no_pnp) {
        control_device* cde = (control_device*)master_devobj->DeviceExtension;
        IoInvalidateDeviceRelations(cde->buspdo, BusRelations);
    }

    ExReleaseResourceLite(&dev_lock);

    return;

fail:
    ObDereferenceObject(c->fileobj);

    if (c->devpath.Buffer)
        ExFreePool(c->devpath.Buffer);

    ExFreePool(c);

    ExReleaseResourceLite(&dev_lock);
}

static uint32_t calc_csum(mdraid_superblock* sb) {
    uint32_t* buf = (uint32_t*)sb;
    uint64_t v = 0;

    uint32_t size = (offsetof(mdraid_superblock, roles) + (2 * sb->array_state.max_dev)) / 4;

    for (uint32_t i = 0; i < size; i++) {
        v += buf[i];
    }

    v -= sb->array_state.sb_csum;

    return (v & 0xffffffff) + (v >> 32);
}

static bool volume_arrival2(PDEVICE_OBJECT devobj, PFILE_OBJECT fileobj, uint64_t offset, uint32_t buflen, mdraid_superblock* sb) {
    NTSTATUS Status;
    uint32_t expected_csum;

    Status = sync_read_phys(devobj, fileobj, offset, buflen, (uint8_t*)sb, true);
    if (!NT_SUCCESS(Status)) {
        ERR("sync_read_phys returned %08x\n", Status);
        return false;
    }

    TRACE("magic: %08x\n", sb->magic);

    if (sb->magic != RAID_MAGIC)
        return false;

    TRACE("RAID device found\n");

    expected_csum = calc_csum(sb);

    if (expected_csum != sb->array_state.sb_csum) {
        WARN("invalid checksum: expected %08x, found %08x\n", expected_csum, sb->array_state.sb_csum);
        return false;
    }

    return true;
}

void volume_arrival(PDRIVER_OBJECT DriverObject, PUNICODE_STRING devpath) {
    NTSTATUS Status;
    PFILE_OBJECT fileobj;
    PDEVICE_OBJECT devobj;

    TRACE("(%p, %.*S)\n", DriverObject, devpath->Length / sizeof(WCHAR), devpath->Buffer);

    Status = IoGetDeviceObjectPointer(devpath, FILE_READ_DATA, &fileobj, &devobj);
    if (!NT_SUCCESS(Status)) {
        ERR("IoGetDeviceObjectPointer returned %08x\n", Status);
        return;
    }

    TRACE("devobj = %p, SectorSize = %lx\n", devobj, devobj->SectorSize);

    uint32_t sector_size = devobj->SectorSize;

    if (sector_size < 4096)
        sector_size = 4096;

    uint32_t buflen = sector_align32((uint32_t)sizeof(mdraid_superblock), sector_size);

    mdraid_superblock* sb = ExAllocatePoolWithTag(PagedPool, buflen, ALLOC_TAG);
    if (!sb) {
        ERR("out of memory\n");
        ObDereferenceObject(fileobj);
        return;
    }

    // version 1.2
    if (volume_arrival2(devobj, fileobj, RAID_12_OFFSET, buflen, sb)) {
        device_found(devobj, fileobj, devpath, sb);
        goto end;
    }

    // version 1.1
    if (volume_arrival2(devobj, fileobj, 0, buflen, sb)) {
        device_found(devobj, fileobj, devpath, sb);
        goto end;
    }

    // version 1.0

    GET_LENGTH_INFORMATION gli;

    Status = dev_ioctl(devobj, fileobj, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &gli, sizeof(GET_LENGTH_INFORMATION), false, NULL);
    if (!NT_SUCCESS(Status)) {
        ERR("IOCTL_DISK_GET_LENGTH_INFO returned %08x\n", Status);
    } else {
        uint64_t offset = gli.Length.QuadPart - 0x2000;
        offset &= ~0xfff;

        if (volume_arrival2(devobj, fileobj, offset, buflen, sb))
            device_found(devobj, fileobj, devpath, sb);
    }

end:
    ObDereferenceObject(fileobj);

    ExFreePool(sb);
}

static NTSTATUS set_close(set_device* set) {
    if (InterlockedDecrement(&set->open_count) == 0 && set->pdo->found_devices == 0) {
        PDEVICE_OBJECT devobj = set->devobj;

        IoDetachDevice(set->attached_device);

        ExDeleteResourceLite(&set->lock);
        IoDeleteDevice(devobj);
    }

    return STATUS_SUCCESS;
}

static void child_removed(set_pdo* pdo, set_child* sc) {
    TRACE("(%p)\n", sc);

    if (sc->disk_info.dev_number < pdo->array_state.max_dev && pdo->roles.dev_roles[sc->disk_info.dev_number] < pdo->array_info.raid_disks &&
        pdo->child_list[pdo->roles.dev_roles[sc->disk_info.dev_number]] == sc) {
        pdo->child_list[pdo->roles.dev_roles[sc->disk_info.dev_number]] = NULL;
        pdo->found_devices--;
        pdo->loaded = false;
    }

    RemoveEntryList(&sc->list_entry);

    ObDereferenceObject(sc->fileobj);

    if (sc->devpath.Buffer)
        ExFreePool(sc->devpath.Buffer);

    ExFreePool(sc);

    // FIXME - send PNP messages(?)

    if (pdo->found_devices == 0) {
        RemoveEntryList(&pdo->list_entry);

        pdo->readonly = true;

        if (pdo->flush_thread_handle) {
            LARGE_INTEGER due_time;

            KeCancelTimer(&pdo->flush_thread_timer);

            due_time.QuadPart = 0;
            KeSetTimer(&pdo->flush_thread_timer, due_time, NULL);

            KeWaitForSingleObject(&pdo->flush_thread_finished, Executive, KernelMode, false, NULL);

            NtClose(pdo->flush_thread_handle);
            pdo->flush_thread_handle = NULL;
        }

        NTSTATUS Status = IoSetDeviceInterfaceState(&pdo->bus_name, false);
        if (!NT_SUCCESS(Status))
            WARN("IoSetDeviceInterfaceState returned %08x\n", Status);

        control_device* cde = (control_device*)master_devobj->DeviceExtension;
        IoInvalidateDeviceRelations(cde->buspdo, BusRelations);
    }

    ExReleaseResourceLite(&pdo->lock);
}

void volume_removal(PDRIVER_OBJECT DriverObject, PUNICODE_STRING devpath) {
    TRACE("(%p, %.*S)\n", DriverObject, devpath->Length / sizeof(WCHAR), devpath->Buffer);

    ExAcquireResourceExclusiveLite(&dev_lock, true);

    LIST_ENTRY* le = dev_list.Flink;

    while (le != &dev_list) {
        set_pdo* sd = CONTAINING_RECORD(le, set_pdo, list_entry);

        ExAcquireResourceExclusiveLite(&sd->lock, true);

        bool found = false;

        LIST_ENTRY* le2 = sd->children.Flink;
        while (le2 != &sd->children) {
            set_child* sc = CONTAINING_RECORD(le2, set_child, list_entry);

            if (sc->devpath.Length == devpath->Length && RtlCompareMemory(sc->devpath.Buffer, devpath->Buffer, devpath->Length) == devpath->Length) {
                child_removed(sd, sc);
                found = true;
                break;
            }

            le2 = le2->Flink;
        }

        if (found)
            break;
        else
            ExReleaseResourceLite(&sd->lock);

        le = le->Flink;
    }

    ExReleaseResourceLite(&dev_lock);
}

static NTSTATUS __stdcall volume_notification(PVOID NotificationStructure, PVOID Context) {
    DEVICE_INTERFACE_CHANGE_NOTIFICATION* dicn = (DEVICE_INTERFACE_CHANGE_NOTIFICATION*)NotificationStructure;
    PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT)Context;

    TRACE("(%p, %p)\n", NotificationStructure, Context);

    if (RtlCompareMemory(&dicn->Event, &GUID_DEVICE_INTERFACE_ARRIVAL, sizeof(GUID)) == sizeof(GUID))
        enqueue_pnp_callback(DriverObject, dicn->SymbolicLinkName, volume_arrival);
    else if (RtlCompareMemory(&dicn->Event, &GUID_DEVICE_INTERFACE_REMOVAL, sizeof(GUID)) == sizeof(GUID))
        enqueue_pnp_callback(DriverObject, dicn->SymbolicLinkName, volume_removal);

    return STATUS_SUCCESS;
}

static void __stdcall DriverUnload(PDRIVER_OBJECT DriverObject) {
    TRACE("(%p)\n", DriverObject);

    if (notification_entry3)
        IoUnregisterPlugPlayNotificationEx(notification_entry3);

    if (notification_entry2)
        IoUnregisterPlugPlayNotificationEx(notification_entry2);

    if (notification_entry)
        IoUnregisterPlugPlayNotificationEx(notification_entry);

    if (master_devobj)
        IoDeleteDevice(master_devobj);

    ExAcquireResourceExclusiveLite(&dev_lock, true);

    while (!IsListEmpty(&dev_list)) {
        set_pdo* sd = CONTAINING_RECORD(RemoveHeadList(&dev_list), set_pdo, list_entry);

        sd->readonly = true;

        if (sd->flush_thread_handle) {
            LARGE_INTEGER due_time;

            KeCancelTimer(&sd->flush_thread_timer);

            due_time.QuadPart = 0;
            KeSetTimer(&sd->flush_thread_timer, due_time, NULL);

            KeWaitForSingleObject(&sd->flush_thread_finished, Executive, KernelMode, false, NULL);

            NtClose(sd->flush_thread_handle);
            sd->flush_thread_handle = NULL;
        }
    }

    ExReleaseResourceLite(&dev_lock);

    control_device* cde = (control_device*)master_devobj->DeviceExtension;
    IoInvalidateDeviceRelations(cde->buspdo, BusRelations);

    ExDeleteResourceLite(&dev_lock);

#ifdef _DEBUG
    if (logger) {
        stop_serial_logger();
        ExFreePool(logger);
    }
#endif
}

static NTSTATUS set_create(set_device* set, PIRP Irp) {
    if (set->pdo->found_devices == 0)
        return STATUS_DEVICE_NOT_READY;

    Irp->IoStatus.Information = FILE_OPENED;

    InterlockedIncrement(&set->open_count);

    return STATUS_SUCCESS;
}

static NTSTATUS mountdev_query_device_name(mdraid_array_info* array_info, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MOUNTDEV_NAME)) {
        Irp->IoStatus.Information = sizeof(MOUNTDEV_NAME);
        return STATUS_BUFFER_TOO_SMALL;
    }

    MOUNTDEV_NAME* name = (MOUNTDEV_NAME*)Irp->AssociatedIrp.SystemBuffer;

    name->NameLength = sizeof(device_prefix) + (36 * sizeof(char16_t));

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < offsetof(MOUNTDEV_NAME, Name[0]) + name->NameLength) {
        Irp->IoStatus.Information = sizeof(MOUNTDEV_NAME);
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlCopyMemory(name->Name, device_prefix, sizeof(device_prefix) - sizeof(char16_t));

    WCHAR* p = &name->Name[(sizeof(device_prefix) / sizeof(char16_t)) - 1];
    for (uint8_t i = 0; i < 16; i++) {
        *p = hex_digit((array_info->set_uuid[i] & 0xf0) >> 4); p++;
        *p = hex_digit(array_info->set_uuid[i] & 0xf); p++;

        if (i == 3 || i == 5 || i == 7 || i == 9) {
            *p = u'-'; p++;
        }
    }

    *p = '}';

    Irp->IoStatus.Information = offsetof(MOUNTDEV_NAME, Name[0]) + name->NameLength;

    return STATUS_SUCCESS;
}

static NTSTATUS mountdev_query_unique_id(mdraid_array_info* array_info, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(MOUNTDEV_UNIQUE_ID)) {
        Irp->IoStatus.Information = sizeof(MOUNTDEV_UNIQUE_ID);
        return STATUS_BUFFER_TOO_SMALL;
    }

    MOUNTDEV_UNIQUE_ID* mduid = (MOUNTDEV_UNIQUE_ID*)Irp->AssociatedIrp.SystemBuffer;
    mduid->UniqueIdLength = sizeof(array_info->set_uuid);

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < offsetof(MOUNTDEV_UNIQUE_ID, UniqueId[0]) + mduid->UniqueIdLength) {
        Irp->IoStatus.Information = sizeof(MOUNTDEV_UNIQUE_ID);
        return STATUS_BUFFER_OVERFLOW;
    }

    RtlCopyMemory(mduid->UniqueId, array_info->set_uuid, sizeof(array_info->set_uuid));

    Irp->IoStatus.Information = offsetof(MOUNTDEV_UNIQUE_ID, UniqueId[0]) + mduid->UniqueIdLength;

    return STATUS_SUCCESS;
}

static NTSTATUS dev_ioctl(PDEVICE_OBJECT DeviceObject, PFILE_OBJECT FileObject, ULONG ControlCode, PVOID InputBuffer,
                          ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, bool Override, IO_STATUS_BLOCK* iosb) {
    PIRP Irp;
    KEVENT Event;
    NTSTATUS Status;
    IO_STATUS_BLOCK IoStatus;

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    Irp = IoBuildDeviceIoControlRequest(ControlCode, DeviceObject, InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize,
                                        false, &Event, &IoStatus);

    if (!Irp)
        return STATUS_INSUFFICIENT_RESOURCES;

    PIO_STACK_LOCATION IrpSp = IoGetNextIrpStackLocation(Irp);

    IrpSp->FileObject = FileObject;

    if (Override)
        IrpSp->Flags |= SL_OVERRIDE_VERIFY_VOLUME;

    Status = IoCallDriver(DeviceObject, Irp);

    if (Status == STATUS_PENDING) {
        KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
        Status = IoStatus.Status;
    }

    if (iosb)
        *iosb = IoStatus;

    return Status;
}

static NTSTATUS check_verify(set_pdo* pdo) {
    ExAcquireResourceSharedLite(&pdo->lock, true);

    LIST_ENTRY* le = pdo->children.Flink;
    while (le != &pdo->children) {
        set_child* c = CONTAINING_RECORD(le, set_child, list_entry);

        NTSTATUS Status = dev_ioctl(c->device, c->fileobj, IOCTL_STORAGE_CHECK_VERIFY, NULL, 0, NULL, 0, false, NULL);
        if (!NT_SUCCESS(Status)) {
            ExReleaseResourceLite(&pdo->lock);
            return Status;
        }

        le = le->Flink;
    }

    ExReleaseResourceLite(&pdo->lock);

    return STATUS_SUCCESS;
}

static NTSTATUS disk_get_drive_geometry(uint64_t array_size, PIRP Irp, PDEVICE_OBJECT devobj) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(DISK_GEOMETRY))
        return STATUS_BUFFER_TOO_SMALL;

    DISK_GEOMETRY* geom = (DISK_GEOMETRY*)Irp->AssociatedIrp.SystemBuffer;

    geom->BytesPerSector = devobj->SectorSize == 0 ? 0x200 : devobj->SectorSize;
    geom->SectorsPerTrack = 0x3f;
    geom->TracksPerCylinder = 0xff;
    geom->Cylinders.QuadPart = array_size / (UInt32x32To64(geom->TracksPerCylinder, geom->SectorsPerTrack) * geom->BytesPerSector);
    geom->MediaType = devobj->Characteristics & FILE_REMOVABLE_MEDIA ? RemovableMedia : FixedMedia;

    Irp->IoStatus.Information = sizeof(DISK_GEOMETRY);

    return STATUS_SUCCESS;
}

static NTSTATUS disk_get_length_info(uint64_t array_size, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(GET_LENGTH_INFORMATION))
        return STATUS_BUFFER_TOO_SMALL;

    GET_LENGTH_INFORMATION* gli = (GET_LENGTH_INFORMATION*)Irp->AssociatedIrp.SystemBuffer;

    gli->Length.QuadPart = array_size;

    Irp->IoStatus.Information = sizeof(GET_LENGTH_INFORMATION);

    return STATUS_SUCCESS;
}

static NTSTATUS set_device_control(set_device* set, PIRP Irp) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (!set->pdo)
        return STATUS_INVALID_DEVICE_REQUEST;

    switch (IrpSp->Parameters.DeviceIoControl.IoControlCode) {
        case IOCTL_MOUNTDEV_QUERY_DEVICE_NAME:
            return mountdev_query_device_name(&set->pdo->array_info, Irp);

        case IOCTL_MOUNTDEV_QUERY_UNIQUE_ID:
            return mountdev_query_unique_id(&set->pdo->array_info, Irp);

        case IOCTL_STORAGE_CHECK_VERIFY:
        case IOCTL_DISK_CHECK_VERIFY:
            return check_verify(set->pdo);

        case IOCTL_DISK_GET_DRIVE_GEOMETRY:
            return disk_get_drive_geometry(set->pdo->array_size, Irp, set->devobj);

        case IOCTL_DISK_GET_LENGTH_INFO:
            return disk_get_length_info(set->pdo->array_size, Irp);

        default:
            ERR("ioctl %x\n", IrpSp->Parameters.DeviceIoControl.IoControlCode);
            return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static NTSTATUS pdo_shutdown(set_pdo* pdo, PIRP Irp) {
    TRACE("(%p, %p)\n", pdo, Irp);

    ExAcquireResourceExclusiveLite(&pdo->lock, true);

    if (pdo->readonly)
        goto end;

    pdo->readonly = true;

    if (pdo->flush_thread_handle) {
        LARGE_INTEGER due_time;

        KeCancelTimer(&pdo->flush_thread_timer);

        due_time.QuadPart = 0;
        KeSetTimer(&pdo->flush_thread_timer, due_time, NULL);

        KeWaitForSingleObject(&pdo->flush_thread_finished, Executive, KernelMode, false, NULL);

        NtClose(pdo->flush_thread_handle);
        pdo->flush_thread_handle = NULL;

        if (pdo->loaded)
            flush_chunks(pdo);
    }

    // FIXME - mark superblocks as clean(?)

end:
    ExReleaseResourceLite(&pdo->lock);

    return STATUS_SUCCESS;
}

static NTSTATUS control_power(PIRP Irp) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->MinorFunction == IRP_MN_SET_POWER || IrpSp->MinorFunction == IRP_MN_QUERY_POWER)
        Irp->IoStatus.Status = STATUS_SUCCESS;

    Status = Irp->IoStatus.Status;
    PoStartNextPowerIrp(Irp);

    return Status;
}

bool is_top_level(PIRP Irp) {
    if (!IoGetTopLevelIrp()) {
        IoSetTopLevelIrp(Irp);
        return true;
    }

    return false;
}

NTSTATUS drv_create(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    switch (*(enum device_type*)DeviceObject->DeviceExtension) {
        case device_type_control:
        case device_type_pdo:
            Irp->IoStatus.Information = FILE_OPENED;
            Status = STATUS_SUCCESS;
            break;

        case device_type_set:
            Status = set_create((set_device*)(DeviceObject->DeviceExtension), Irp);
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(NULL);

    FsRtlExitFileSystem();

    return Status;
}

NTSTATUS drv_device_control(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    switch (*(enum device_type*)DeviceObject->DeviceExtension) {
        case device_type_set:
            Status = set_device_control((set_device*)(DeviceObject->DeviceExtension), Irp);
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(NULL);

    FsRtlExitFileSystem();

    return Status;
}

NTSTATUS drv_shutdown(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    switch (*(enum device_type*)DeviceObject->DeviceExtension) {
        case device_type_pdo:
            Status = pdo_shutdown((set_pdo*)(DeviceObject->DeviceExtension), Irp);
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(NULL);

    FsRtlExitFileSystem();

    return Status;
}

NTSTATUS drv_power(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    switch (*(enum device_type*)DeviceObject->DeviceExtension) {
        case device_type_control:
            Status = control_power(Irp);
            break;

        default:
            Status = Irp->IoStatus.Status;
            PoStartNextPowerIrp(Irp);
            break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(NULL);

    FsRtlExitFileSystem();

    return Status;
}

static void check_cpu() {
    int cpuInfo[4];
   __cpuid(cpuInfo, 1);
   have_sse2 = cpuInfo[3] & (1 << 26);
}

static NTSTATUS drv_close(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    switch (*(enum device_type*)DeviceObject->DeviceExtension) {
        case device_type_set:
            Status = set_close((set_device*)(DeviceObject->DeviceExtension));
            break;

        case device_type_pdo:
            Status = STATUS_SUCCESS;
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    if (top_level)
        IoSetTopLevelIrp(NULL);

    FsRtlExitFileSystem();

    return Status;
}

static void get_registry_value(HANDLE h, const WCHAR* string, ULONG type, void* val, ULONG size) {
    ULONG kvfilen;
    UNICODE_STRING us;
    NTSTATUS Status;

    RtlInitUnicodeString(&us, string);

    Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, NULL, 0, &kvfilen);

    if ((Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW) && kvfilen > 0) {
        KEY_VALUE_FULL_INFORMATION* kvfi = ExAllocatePoolWithTag(PagedPool, kvfilen, ALLOC_TAG);

        if (!kvfi) {
            ERR("out of memory\n");
            ZwClose(h);
            return;
        }

        Status = ZwQueryValueKey(h, &us, KeyValueFullInformation, kvfi, kvfilen, &kvfilen);

        if (NT_SUCCESS(Status)) {
            if (kvfi->Type == type && kvfi->DataLength >= size) {
                RtlCopyMemory(val, ((UINT8*)kvfi) + kvfi->DataOffset, size);
            } else {
                Status = ZwDeleteValueKey(h, &us);
                if (!NT_SUCCESS(Status))
                    ERR("ZwDeleteValueKey returned %08x\n", Status);

                Status = ZwSetValueKey(h, &us, 0, type, val, size);
                if (!NT_SUCCESS(Status))
                    ERR("ZwSetValueKey returned %08x\n", Status);
            }
        }

        ExFreePool(kvfi);
    } else if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
        Status = ZwSetValueKey(h, &us, 0, type, val, size);

        if (!NT_SUCCESS(Status))
            ERR("ZwSetValueKey returned %08x\n", Status);
    } else
        ERR("ZwQueryValueKey returned %08x\n", Status);
}

void read_registry(PUNICODE_STRING regpath) {
    OBJECT_ATTRIBUTES oa;
    NTSTATUS Status;
    HANDLE h;
    ULONG dispos;

    InitializeObjectAttributes(&oa, regpath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    Status = ZwCreateKey(&h, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &oa, 0, NULL, REG_OPTION_NON_VOLATILE, &dispos);

    if (!NT_SUCCESS(Status)) {
        ERR("ZwCreateKey returned %08x\n", Status);
        return;
    }

#ifdef _DEBUG
    get_registry_value(h, L"DebugLogLevel", REG_DWORD, &debug_log_level, sizeof(debug_log_level));
#endif

    ZwClose(h);
}

static NTSTATUS set_system_control(set_device* set, PIRP Irp, bool* no_complete) {
    *no_complete = true;

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(set->attached_device, Irp);
}

static NTSTATUS control_system_control(control_device* control, PIRP Irp, bool* no_complete) {
    *no_complete = true;

    IoSkipCurrentIrpStackLocation(Irp);
    return IoCallDriver(control->attached_device, Irp);
}

static NTSTATUS drv_system_control(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    bool no_complete = false;

    switch (*(enum device_type*)DeviceObject->DeviceExtension) {
        case device_type_control:
            Status = control_system_control((control_device*)(DeviceObject->DeviceExtension), Irp, &no_complete);
            break;

        case device_type_set:
            Status = set_system_control((set_device*)(DeviceObject->DeviceExtension), Irp, &no_complete);
            break;

        default:
            Status = Irp->IoStatus.Status;
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

NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS Status;
    RTL_OSVERSIONINFOW ver;

    ver.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

    Status = RtlGetVersion(&ver);
    if (!NT_SUCCESS(Status)) {
        ERR("RtlGetVersion returned %08lx\n", Status);
        return Status;
    }

    is_windows_8 = ver.dwMajorVersion > 6 || (ver.dwMajorVersion == 6 && ver.dwMinorVersion >= 2);

    drvobj = DriverObject;

    DriverObject->DriverUnload = DriverUnload;
    DriverObject->DriverExtension->AddDevice = AddDevice;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = (PDRIVER_DISPATCH)drv_create;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = (PDRIVER_DISPATCH)drv_close;
    DriverObject->MajorFunction[IRP_MJ_READ] = (PDRIVER_DISPATCH)drv_read;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = (PDRIVER_DISPATCH)drv_write;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)drv_device_control;
    DriverObject->MajorFunction[IRP_MJ_PNP] = (PDRIVER_DISPATCH)drv_pnp;
    DriverObject->MajorFunction[IRP_MJ_POWER] = (PDRIVER_DISPATCH)drv_power;
    DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = (PDRIVER_DISPATCH)drv_shutdown;
    DriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = (PDRIVER_DISPATCH)drv_system_control;

    read_registry(RegistryPath);

#ifdef _DEBUG
    if (debug_log_level > 0) {
        NTSTATUS Status;
        UNICODE_STRING us;

        logger = ExAllocatePoolWithTag(NonPagedPool, sizeof(serial_logger), ALLOC_TAG);
        if (!logger) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        init_serial_logger();
    }
#endif

    TRACE("(%p, %.*S)\n", DriverObject, RegistryPath->Length / sizeof(WCHAR), RegistryPath->Buffer);

    check_cpu();

    UNICODE_STRING device_nameW;

    device_nameW.Buffer = (WCHAR*)device_name;
    device_nameW.Length = device_nameW.MaximumLength = sizeof(device_name) - sizeof(WCHAR);

    Status = IoCreateDevice(DriverObject, sizeof(control_device), &device_nameW, FILE_DEVICE_DISK,
                            FILE_DEVICE_SECURE_OPEN, false, &master_devobj);
    if (!NT_SUCCESS(Status)) {
        ERR("IoCreateDevice returned %08x\n", Status);
        return Status;
    }

    control_device* cde = (control_device*)master_devobj->DeviceExtension;
    cde->type = device_type_control;

    ExInitializeResourceLite(&dev_lock);

    InitializeListHead(&dev_list);

    master_devobj->Flags &= ~DO_DEVICE_INITIALIZING;

    Status = IoReportDetectedDevice(drvobj, InterfaceTypeUndefined, 0xFFFFFFFF, 0xFFFFFFFF,
                                    NULL, NULL, 0, &cde->buspdo);
    if (!NT_SUCCESS(Status)) {
        ERR("IoReportDetectedDevice returned %08x\n", Status);
        IoDeleteDevice(master_devobj);
        return Status;
    }

    Status = IoRegisterDeviceInterface(cde->buspdo, &WinMDBusInterface, NULL, &cde->bus_name);
    if (!NT_SUCCESS(Status))
        WARN("IoRegisterDeviceInterface returned %08x\n", Status);

    cde->attached_device = IoAttachDeviceToDeviceStack(master_devobj, cde->buspdo);

    Status = IoSetDeviceInterfaceState(&cde->bus_name, true);
    if (!NT_SUCCESS(Status))
        WARN("IoSetDeviceInterfaceState returned %08x\n", Status);

    IoInvalidateDeviceRelations(cde->buspdo, BusRelations);

    Status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange, PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                            (PVOID)&GUID_DEVINTERFACE_VOLUME, DriverObject, volume_notification, DriverObject, &notification_entry);
    if (!NT_SUCCESS(Status)) {
        ERR("IoRegisterPlugPlayNotification returned %08x\n", Status);
        IoDeleteDevice(master_devobj);
        return Status;
    }

    Status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange, PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                            (PVOID)&GUID_DEVINTERFACE_HIDDEN_VOLUME, DriverObject, volume_notification, DriverObject, &notification_entry2);
    if (!NT_SUCCESS(Status)) {
        ERR("IoRegisterPlugPlayNotification returned %08x\n", Status);
        IoUnregisterPlugPlayNotificationEx(notification_entry);
        IoDeleteDevice(master_devobj);
        return Status;
    }

    Status = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange, PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                            (PVOID)&GUID_DEVINTERFACE_DISK, DriverObject, volume_notification, DriverObject, &notification_entry3);
    if (!NT_SUCCESS(Status)) {
        ERR("IoRegisterPlugPlayNotification returned %08x\n", Status);
        IoUnregisterPlugPlayNotificationEx(notification_entry2);
        IoUnregisterPlugPlayNotificationEx(notification_entry);
        IoDeleteDevice(master_devobj);
        return Status;
    }

    return STATUS_SUCCESS;
}
