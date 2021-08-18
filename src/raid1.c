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

typedef struct {
    PIRP Irp;
    KEVENT Event;
    IO_STATUS_BLOCK iosb;
    NTSTATUS Status;
} io_context_raid1;

NTSTATUS read_raid1(set_pdo* pdo, PIRP Irp, bool* no_complete) {
    NTSTATUS Status;

    ExAcquireResourceSharedLite(&pdo->lock, true);

    pdo->read_device++;

    set_child* c = pdo->child_list[pdo->read_device % pdo->array_info.raid_disks];

    IoCopyCurrentIrpStackLocationToNext(Irp);

    PIO_STACK_LOCATION IrpSp = IoGetNextIrpStackLocation(Irp);

    IrpSp->FileObject = c->fileobj;
    IrpSp->Parameters.Read.ByteOffset.QuadPart += c->disk_info.data_offset * 512;

    *no_complete = true;

    Status = IoCallDriver(c->device, Irp);

    ExReleaseResourceLite(&pdo->lock);

    return Status;
}

_Function_class_(IO_COMPLETION_ROUTINE)
static NTSTATUS __stdcall io_completion_raid1(PDEVICE_OBJECT devobj, PIRP Irp, PVOID ctx) {
    io_context_raid1* context = ctx;

    context->iosb = Irp->IoStatus;
    KeSetEvent(&context->Event, 0, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS write_raid1(set_pdo* pdo, PIRP Irp) {
    NTSTATUS Status;

    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    io_context_raid1* ctxs = ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context_raid1) * pdo->array_info.raid_disks, ALLOC_TAG);
    if (!ctxs) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ctxs, sizeof(io_context_raid1) * pdo->array_info.raid_disks);

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        ctxs[i].Irp = IoAllocateIrp(pdo->child_list[i]->device->StackSize, false);

        if (!ctxs[i].Irp) {
            ERR("IoAllocateIrp failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        PIO_STACK_LOCATION IrpSp2 = IoGetNextIrpStackLocation(ctxs[i].Irp);
        IrpSp2->MajorFunction = IRP_MJ_WRITE;
        IrpSp2->FileObject = pdo->child_list[i]->fileobj;

        ctxs[i].Irp->MdlAddress = Irp->MdlAddress;

        IrpSp2->Parameters.Write.Length = IrpSp->Parameters.Write.Length;
        IrpSp2->Parameters.Write.ByteOffset.QuadPart = IrpSp->Parameters.Write.ByteOffset.QuadPart + (pdo->child_list[i]->disk_info.data_offset * 512);

        ctxs[i].Irp->UserIosb = &ctxs[i].iosb;

        KeInitializeEvent(&ctxs[i].Event, NotificationEvent, false);
        ctxs[i].Irp->UserEvent = &ctxs[i].Event;

        IoSetCompletionRoutine(ctxs[i].Irp, io_completion_raid1, &ctxs[i], true, true, true);
    }

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        ctxs[i].Status = IoCallDriver(pdo->child_list[i]->device, ctxs[i].Irp);
        if (!NT_SUCCESS(ctxs[i].Status))
            ERR("IoCallDriver returned %08x\n", ctxs[i].Status);
    }

    Status = STATUS_SUCCESS;

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].Status == STATUS_PENDING) {
            KeWaitForSingleObject(&ctxs[i].Event, Executive, KernelMode, false, NULL);
            ctxs[i].Status = ctxs[i].iosb.Status;
        }

        if (!NT_SUCCESS(ctxs[i].Status))
            Status = ctxs[i].Status;
    }

end:
    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].Irp)
            IoFreeIrp(ctxs[i].Irp);
    }

    ExFreePool(ctxs);

    return Status;
}
