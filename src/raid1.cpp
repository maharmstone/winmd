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

NTSTATUS set_pdo::read_raid1(PIRP Irp, bool* no_complete) {
    NTSTATUS Status;

    ExAcquireResourceSharedLite(&lock, true);

    read_device++;

    auto c = child_list[read_device % array_info.raid_disks];

    IoCopyCurrentIrpStackLocationToNext(Irp);

    PIO_STACK_LOCATION IrpSp = IoGetNextIrpStackLocation(Irp);

    IrpSp->FileObject = c->fileobj;
    IrpSp->Parameters.Read.ByteOffset.QuadPart += c->disk_info.data_offset * 512;

    *no_complete = true;

    Status = IoCallDriver(c->device, Irp);

    ExReleaseResourceLite(&lock);

    return Status;
}

NTSTATUS set_pdo::write_raid1(PIRP Irp) {
    NTSTATUS Status;

    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);

    auto ctxs = (io_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context) * array_info.raid_disks, ALLOC_TAG);
    if (!ctxs) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ctxs, sizeof(io_context) * array_info.raid_disks);

    for (unsigned int i = 0; i < array_info.raid_disks; i++) {
        ctxs[i].Irp = IoAllocateIrp(child_list[i]->device->StackSize, false);

        if (!ctxs[i].Irp) {
            ERR("IoAllocateIrp failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        auto IrpSp2 = IoGetNextIrpStackLocation(ctxs[i].Irp);
        IrpSp2->MajorFunction = IRP_MJ_WRITE;
        IrpSp2->FileObject = child_list[i]->fileobj;

        ctxs[i].Irp->MdlAddress = Irp->MdlAddress;

        IrpSp2->Parameters.Write.Length = IrpSp->Parameters.Write.Length;
        IrpSp2->Parameters.Write.ByteOffset.QuadPart = IrpSp->Parameters.Write.ByteOffset.QuadPart + (child_list[i]->disk_info.data_offset * 512);

        ctxs[i].Irp->UserIosb = &ctxs[i].iosb;

        KeInitializeEvent(&ctxs[i].Event, NotificationEvent, false);
        ctxs[i].Irp->UserEvent = &ctxs[i].Event;

        IoSetCompletionRoutine(ctxs[i].Irp, io_completion, &ctxs[i], true, true, true);
    }

    for (unsigned int i = 0; i < array_info.raid_disks; i++) {
        ctxs[i].Status = IoCallDriver(child_list[i]->device, ctxs[i].Irp);
        if (!NT_SUCCESS(ctxs[i].Status))
            ERR("IoCallDriver returned %08x\n", ctxs[i].Status);
    }

    Status = STATUS_SUCCESS;

    for (unsigned int i = 0; i < array_info.raid_disks; i++) {
        if (ctxs[i].Status == STATUS_PENDING) {
            KeWaitForSingleObject(&ctxs[i].Event, Executive, KernelMode, false, nullptr);
            ctxs[i].Status = ctxs[i].iosb.Status;
        }

        if (!NT_SUCCESS(ctxs[i].Status))
            Status = ctxs[i].Status;
    }

end:
    for (unsigned int i = 0; i < array_info.raid_disks; i++) {
        if (ctxs[i].Irp)
            IoFreeIrp(ctxs[i].Irp);
    }

    ExFreePool(ctxs);

    return Status;
}
