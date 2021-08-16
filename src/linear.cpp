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

struct io_context_linear {
    PIRP Irp;
    KEVENT Event;
    IO_STATUS_BLOCK iosb;
    NTSTATUS Status;
    PMDL mdl;
    LIST_ENTRY list_entry;
};

static NTSTATUS __stdcall io_completion_linear(PDEVICE_OBJECT, PIRP Irp, PVOID ctx) {
    io_context_linear* context = (io_context_linear*)ctx;

    context->iosb = Irp->IoStatus;
    KeSetEvent(&context->Event, 0, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

static NTSTATUS io_linear2(set_pdo* pdo, PIRP Irp, uint64_t offset, uint32_t start_disk, bool write) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    uint32_t length = write ? IrpSp->Parameters.Write.Length : IrpSp->Parameters.Read.Length;
    LIST_ENTRY ctxs;
    uint8_t* va = (uint8_t*)MmGetMdlVirtualAddress(Irp->MdlAddress);

    InitializeListHead(&ctxs);

    for (uint32_t i = start_disk; i < pdo->array_info.raid_disks; i++) {
        uint32_t io_length = (uint32_t)min(length, (pdo->child_list[i]->disk_info.data_size * 512) - offset);

        io_context_linear* last = (io_context_linear*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context_linear), ALLOC_TAG);
        if (!last) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto fail;
        }

        last->Irp = IoAllocateIrp(pdo->child_list[i]->device->StackSize, false);
        if (!last->Irp) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            ExFreePool(last);
            goto fail;
        }

        last->Irp->UserIosb = &last->iosb;

        KeInitializeEvent(&last->Event, NotificationEvent, false);
        last->Irp->UserEvent = &last->Event;

        IoSetCompletionRoutine(last->Irp, io_completion_linear, last, true, true, true);

        last->Status = STATUS_SUCCESS;

        last->mdl = nullptr;

        InsertTailList(&ctxs, &last->list_entry);

        if (!NT_SUCCESS(last->Status)) {
            ERR("io_context_linear constructor returned %08x\n", last->Status);
            Status = last->Status;
            goto fail;
        }

        last->mdl = IoAllocateMdl(va, io_length, false, false, nullptr);
        if (!last->mdl) {
            ERR("IoAllocateMdl failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto fail;
        }

        last->Irp->MdlAddress = last->mdl;

        IoBuildPartialMdl(Irp->MdlAddress, last->mdl, va, io_length);

        PIO_STACK_LOCATION IrpSp2 = IoGetNextIrpStackLocation(last->Irp);

        IrpSp2->FileObject = pdo->child_list[i]->fileobj;

        if (write) {
            IrpSp2->MajorFunction = IRP_MJ_WRITE;
            IrpSp2->Parameters.Write.ByteOffset.QuadPart = offset + (pdo->child_list[i]->disk_info.data_offset * 512);
            IrpSp2->Parameters.Write.Length = io_length;
        } else {
            IrpSp2->MajorFunction = IRP_MJ_READ;
            IrpSp2->Parameters.Read.ByteOffset.QuadPart = offset + (pdo->child_list[i]->disk_info.data_offset * 512);
            IrpSp2->Parameters.Read.Length = io_length;
        }

        last->Status = IoCallDriver(pdo->child_list[i]->device, last->Irp);

        length -= io_length;

        if (length == 0)
            break;

        offset = 0;
        va += io_length;
    }

    Status = STATUS_SUCCESS;

    while (!IsListEmpty(&ctxs)) {
        io_context_linear* ctx = CONTAINING_RECORD(RemoveHeadList(&ctxs), io_context_linear, list_entry);

        if (ctx->Status == STATUS_PENDING) {
            KeWaitForSingleObject(&ctx->Event, Executive, KernelMode, false, nullptr);
            ctx->Status = ctx->iosb.Status;
        }

        if (!NT_SUCCESS(ctx->Status)) {
            ERR("device returned %08x\n", ctx->Status);
            Status = ctx->Status;
        }

        if (ctx->mdl)
            IoFreeMdl(ctx->mdl);

        if (ctx->Irp)
            IoFreeIrp(ctx->Irp);

        ExFreePool(ctx);
    }

    return Status;

fail:
    while (!IsListEmpty(&ctxs)) {
        io_context_linear* ctx = CONTAINING_RECORD(RemoveHeadList(&ctxs), io_context_linear, list_entry);

        if (ctx->mdl)
            IoFreeMdl(ctx->mdl);

        if (ctx->Irp)
            IoFreeIrp(ctx->Irp);

        ExFreePool(ctx);
    }

    return Status;
}

NTSTATUS read_linear(set_pdo* pdo, PIRP Irp, bool* no_complete) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    uint64_t offset = IrpSp->Parameters.Read.ByteOffset.QuadPart;
    uint32_t length = IrpSp->Parameters.Read.Length;

    ExAcquireResourceSharedLite(&pdo->lock, true);

    for (uint32_t i = 0; i < pdo->array_info.raid_disks; i++) {
        if (offset < (pdo->child_list[i]->disk_info.data_size * 512)) {
            NTSTATUS Status;

            if (offset + length < (pdo->child_list[i]->disk_info.data_size * 512) || i == pdo->array_info.raid_disks - 1) {
                set_child* c = pdo->child_list[i];

                IoCopyCurrentIrpStackLocationToNext(Irp);

                PIO_STACK_LOCATION IrpSp2 = IoGetNextIrpStackLocation(Irp);

                IrpSp2->FileObject = pdo->child_list[i]->fileobj;
                IrpSp2->Parameters.Read.ByteOffset.QuadPart = offset + (c->disk_info.data_offset * 512);

                if (i == pdo->array_info.raid_disks - 1)
                    IrpSp2->Parameters.Read.Length = (uint32_t)min(IrpSp2->Parameters.Read.Length, ((pdo->child_list[i]->disk_info.data_size * 512) - offset));

                *no_complete = true;

                Status = IoCallDriver(c->device, Irp);
            } else
                Status = io_linear2(pdo, Irp, offset, i, false);

            ExReleaseResourceLite(&pdo->lock);

            return Status;
        }

        offset -= pdo->child_list[i]->disk_info.data_size * 512;
    }

    ExReleaseResourceLite(&pdo->lock);

    return STATUS_INVALID_PARAMETER;
}

NTSTATUS write_linear(set_pdo* pdo, PIRP Irp, bool* no_complete) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    uint64_t offset = IrpSp->Parameters.Write.ByteOffset.QuadPart;
    uint32_t length = IrpSp->Parameters.Write.Length;

    for (uint32_t i = 0; i < pdo->array_info.raid_disks; i++) {
        if (offset < (pdo->child_list[i]->disk_info.data_size * 512)) {
            if (offset + length < (pdo->child_list[i]->disk_info.data_size * 512) || i == pdo->array_info.raid_disks - 1) {
                set_child* c = pdo->child_list[i];

                IoCopyCurrentIrpStackLocationToNext(Irp);

                PIO_STACK_LOCATION IrpSp2 = IoGetNextIrpStackLocation(Irp);

                IrpSp2->FileObject = pdo->child_list[i]->fileobj;
                IrpSp2->Parameters.Write.ByteOffset.QuadPart = offset + (c->disk_info.data_offset * 512);

                if (i == pdo->array_info.raid_disks - 1)
                    IrpSp2->Parameters.Write.Length = (uint32_t)min(IrpSp2->Parameters.Write.Length, ((pdo->child_list[i]->disk_info.data_size * 512) - offset));

                *no_complete = true;

                return IoCallDriver(c->device, Irp);
            } else
                return io_linear2(pdo, Irp, offset, i, true);
        }

        offset -= pdo->child_list[i]->disk_info.data_size * 512;
    }

    return STATUS_INVALID_PARAMETER;
}
