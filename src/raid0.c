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
    set_child* sc;
    uint64_t stripe_start;
    uint64_t stripe_end;
    PMDL mdl;
    PFN_NUMBER* pfns;
    PFN_NUMBER* pfnp;
} io_context_raid0;

_Function_class_(IO_COMPLETION_ROUTINE)
static NTSTATUS __stdcall io_completion_raid0(PDEVICE_OBJECT devobj, PIRP Irp, PVOID ctx) {
    io_context_raid0* context = ctx;

    context->iosb = Irp->IoStatus;
    KeSetEvent(&context->Event, 0, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS read_raid0(set_pdo* pdo, PIRP Irp, bool* no_complete) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    uint64_t offset = IrpSp->Parameters.Read.ByteOffset.QuadPart;
    uint32_t length = IrpSp->Parameters.Read.Length;
    bool mdl_locked = true;
    uint8_t* tmpbuf = NULL;
    PMDL tmpmdl = NULL;

    if (pdo->array_info.chunksize == 0 || (pdo->array_info.chunksize * 512) % PAGE_SIZE != 0)
        return STATUS_INTERNAL_ERROR;

    uint64_t start_chunk = offset / (pdo->array_info.chunksize * 512);
    uint64_t end_chunk = (offset + length - 1) / (pdo->array_info.chunksize * 512);

    if (start_chunk == end_chunk) { // small reads, on one device
        set_child* c = pdo->child_list[start_chunk % pdo->array_info.raid_disks];

        IoCopyCurrentIrpStackLocationToNext(Irp);

        PIO_STACK_LOCATION IrpSp2 = IoGetNextIrpStackLocation(Irp);

        uint64_t start = (start_chunk / pdo->array_info.raid_disks) * (pdo->array_info.chunksize * 512);

        start += offset % (pdo->array_info.chunksize * 512);
        start += c->disk_info.data_offset * 512;

        IrpSp2->FileObject = c->fileobj;
        IrpSp2->Parameters.Read.ByteOffset.QuadPart = start;

        *no_complete = true;

        return IoCallDriver(c->device, Irp);
    }

    uint64_t startoff, endoff;
    uint32_t startoffstripe, endoffstripe;

    uint32_t stripe_length = pdo->array_info.chunksize * 512;

    uint32_t skip_first = offset % PAGE_SIZE;

    offset -= skip_first;
    length += skip_first;

    get_raid0_offset(offset, stripe_length, pdo->array_info.raid_disks, &startoff, &startoffstripe);
    get_raid0_offset(offset + length - 1, stripe_length, pdo->array_info.raid_disks, &endoff, &endoffstripe);

    io_context_raid0* ctxs = ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context_raid0) * pdo->array_info.raid_disks, ALLOC_TAG);
    if (!ctxs) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ctxs, sizeof(io_context_raid0) * pdo->array_info.raid_disks);

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (startoffstripe > i)
            ctxs[i].stripe_start = startoff - (startoff % stripe_length) + stripe_length;
        else if (startoffstripe == i)
            ctxs[i].stripe_start = startoff;
        else
            ctxs[i].stripe_start = startoff - (startoff % stripe_length);

        if (endoffstripe > i)
            ctxs[i].stripe_end = endoff - (endoff % stripe_length) + stripe_length;
        else if (endoffstripe == i)
            ctxs[i].stripe_end = endoff + 1;
        else
            ctxs[i].stripe_end = endoff - (endoff % stripe_length);
    }

    NTSTATUS Status;

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].stripe_end != ctxs[i].stripe_start) {
            ctxs[i].Irp = IoAllocateIrp(pdo->child_list[i]->device->StackSize, false);

            if (!ctxs[i].Irp) {
                ERR("IoAllocateIrp failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            PIO_STACK_LOCATION IrpSp2 = IoGetNextIrpStackLocation(ctxs[i].Irp);
            IrpSp2->MajorFunction = IRP_MJ_READ;

            ctxs[i].mdl = IoAllocateMdl(NULL, (ULONG)(ctxs[i].stripe_end - ctxs[i].stripe_start), false, false, NULL);
            if (!ctxs[i].mdl) {
                ERR("IoAllocateMdl failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            ctxs[i].mdl->MdlFlags |= MDL_PARTIAL;

            ctxs[i].Irp->MdlAddress = ctxs[i].mdl;

            IrpSp2->FileObject = pdo->child_list[i]->fileobj;
            IrpSp2->Parameters.Read.Length = (ULONG)(ctxs[i].stripe_end - ctxs[i].stripe_start);
            IrpSp2->Parameters.Read.ByteOffset.QuadPart = ctxs[i].stripe_start + (pdo->child_list[i]->disk_info.data_offset * 512);

            ctxs[i].Irp->UserIosb = &ctxs[i].iosb;

            KeInitializeEvent(&ctxs[i].Event, NotificationEvent, false);
            ctxs[i].Irp->UserEvent = &ctxs[i].Event;

            IoSetCompletionRoutine(ctxs[i].Irp, io_completion_raid0, &ctxs[i], true, true, true);
        } else
            ctxs[i].Status = STATUS_SUCCESS;
    }

    mdl_locked = Irp->MdlAddress->MdlFlags & (MDL_PAGES_LOCKED | MDL_PARTIAL);

    if (!mdl_locked) {
        Status = STATUS_SUCCESS;

        try {
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoWriteAccess);
        } except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (!NT_SUCCESS(Status)) {
            ERR("MmProbeAndLockPages threw exception %08x\n", Status);
            mdl_locked = true;
            goto end;
        }
    }

    if (Irp->MdlAddress->ByteOffset != 0 || skip_first != 0) {
        tmpbuf = ExAllocatePoolWithTag(NonPagedPool, length, ALLOC_TAG);
        if (!tmpbuf) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        tmpmdl = IoAllocateMdl(tmpbuf, length, false, false, NULL);
        if (!tmpmdl) {
            ERR("IoAllocateMdl failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        MmBuildMdlForNonPagedPool(tmpmdl);
    }

    {
        uint32_t pos = 0;
        uint32_t stripe = startoffstripe;
        MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

        for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
            if (ctxs[i].mdl)
                ctxs[i].pfnp = ctxs[i].pfns = MmGetMdlPfnArray(ctxs[i].mdl);
        }

        PPFN_NUMBER src_pfns = MmGetMdlPfnArray((tmpmdl ? tmpmdl : Irp->MdlAddress));

        while (pos < length) {
            uint32_t len, pages;

            if (pos == 0) {
                len = stripe_length - (startoff % stripe_length);

                if (len % PAGE_SIZE != 0) {
                    pages = len / PAGE_SIZE;
                    pages++;
                } else
                    pages = len / PAGE_SIZE;
            } else {
                len = stripe_length;
                pages = len / PAGE_SIZE;
            }

            if (pos + len > length) {
                len = length - pos;

                if (len % PAGE_SIZE != 0) {
                    pages = len / PAGE_SIZE;
                    pages++;
                } else
                    pages = len / PAGE_SIZE;
            }

            RtlCopyMemory(ctxs[stripe].pfnp, src_pfns, sizeof(PFN_NUMBER) * pages);
            src_pfns = &src_pfns[pages];
            ctxs[stripe].pfnp = &ctxs[stripe].pfnp[pages];

            pos += len;

            stripe = (stripe + 1) % pdo->array_info.raid_disks;
        }
    }

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].Irp) {
            ctxs[i].Status = IoCallDriver(pdo->child_list[i]->device, ctxs[i].Irp);
            if (!NT_SUCCESS(ctxs[i].Status))
                ERR("IoCallDriver returned %08x\n", ctxs[i].Status);
        }
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

    if (tmpbuf) {
        PVOID dest = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

        RtlCopyMemory(dest, tmpbuf + skip_first, length - skip_first);
    }

end:
    if (!mdl_locked)
        MmUnlockPages(Irp->MdlAddress);

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].mdl)
            IoFreeMdl(ctxs[i].mdl);

        if (ctxs[i].Irp)
            IoFreeIrp(ctxs[i].Irp);
    }

    ExFreePool(ctxs);

    if (tmpmdl)
        IoFreeMdl(tmpmdl);

    if (tmpbuf)
        ExFreePool(tmpbuf);

    return Status;
}

NTSTATUS write_raid0(set_pdo* pdo, PIRP Irp, bool* no_complete) {
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    uint64_t offset = IrpSp->Parameters.Write.ByteOffset.QuadPart;
    uint32_t length = IrpSp->Parameters.Write.Length;
    bool mdl_locked = true;
    uint8_t* tmpbuf = NULL;
    PMDL tmpmdl = NULL;
    io_context_raid0* ctxs = NULL;
    io_context_raid0 first_bit;

    if (pdo->array_info.chunksize == 0 || (pdo->array_info.chunksize * 512) % PAGE_SIZE != 0)
        return STATUS_INTERNAL_ERROR;

    uint64_t start_chunk = offset / (pdo->array_info.chunksize * 512);
    uint64_t end_chunk = (offset + length - 1) / (pdo->array_info.chunksize * 512);

    if (start_chunk == end_chunk) { // small write, on one device
        set_child* c = pdo->child_list[start_chunk % pdo->array_info.raid_disks];

        IoCopyCurrentIrpStackLocationToNext(Irp);

        PIO_STACK_LOCATION IrpSp2 = IoGetNextIrpStackLocation(Irp);

        uint64_t start = (start_chunk / pdo->array_info.raid_disks) * (pdo->array_info.chunksize * 512);

        start += offset % (pdo->array_info.chunksize * 512);
        start += c->disk_info.data_offset * 512;

        IrpSp2->FileObject = c->fileobj;
        IrpSp2->Parameters.Write.ByteOffset.QuadPart = start;

        *no_complete = true;

        return IoCallDriver(c->device, Irp);
    }

    uint64_t startoff, endoff;
    uint32_t startoffstripe, endoffstripe;
    uint32_t stripe_length = pdo->array_info.chunksize * 512;

    uint32_t skip_first = offset % PAGE_SIZE ? (PAGE_SIZE - (offset % PAGE_SIZE)) : 0;
    NTSTATUS Status;

    mdl_locked = Irp->MdlAddress->MdlFlags & (MDL_PAGES_LOCKED | MDL_PARTIAL);

    if (!mdl_locked) {
        Status = STATUS_SUCCESS;

        try {
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoReadAccess);
        } except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (!NT_SUCCESS(Status)) {
            ERR("MmProbeAndLockPages threw exception %08x\n", Status);
            return Status;
        }
    }

    first_bit.Irp = NULL;
    first_bit.mdl = NULL;

    if (skip_first != 0) {
        first_bit.sc = pdo->child_list[start_chunk % pdo->array_info.raid_disks];
        first_bit.Irp = IoAllocateIrp(first_bit.sc->device->StackSize, false);

        if (!first_bit.Irp) {
            ERR("IoAllocateIrp failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end2;
        }

        PIO_STACK_LOCATION IrpSp2 = IoGetNextIrpStackLocation(first_bit.Irp);
        IrpSp2->MajorFunction = IRP_MJ_WRITE;

        PVOID addr = MmGetMdlVirtualAddress(Irp->MdlAddress);

        first_bit.mdl = IoAllocateMdl(addr, skip_first, false, false, NULL);
        if (!first_bit.mdl) {
            ERR("IoAllocateMdl failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end2;
        }

        IoBuildPartialMdl(Irp->MdlAddress, first_bit.mdl, addr, skip_first);

        first_bit.Irp->MdlAddress = first_bit.mdl;

        uint64_t start = (start_chunk / pdo->array_info.raid_disks) * (pdo->array_info.chunksize * 512);

        start += offset % (pdo->array_info.chunksize * 512);
        start += first_bit.sc->disk_info.data_offset * 512;

        IrpSp2->FileObject = first_bit.sc->fileobj;
        IrpSp2->Parameters.Write.Length = skip_first;
        IrpSp2->Parameters.Write.ByteOffset.QuadPart = start;

        first_bit.Irp->UserIosb = &first_bit.iosb;

        KeInitializeEvent(&first_bit.Event, NotificationEvent, false);
        first_bit.Irp->UserEvent = &first_bit.Event;

        IoSetCompletionRoutine(first_bit.Irp, io_completion_raid0, &first_bit, true, true, true);

        offset += skip_first;
        length -= skip_first;
    }

    get_raid0_offset(offset, stripe_length, pdo->array_info.raid_disks, &startoff, &startoffstripe);
    get_raid0_offset(offset + length - 1, stripe_length, pdo->array_info.raid_disks, &endoff, &endoffstripe);

    ctxs = ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context_raid0) * pdo->array_info.raid_disks, ALLOC_TAG);
    if (!ctxs) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end2;
    }

    RtlZeroMemory(ctxs, sizeof(io_context_raid0) * pdo->array_info.raid_disks);

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (startoffstripe > i)
            ctxs[i].stripe_start = startoff - (startoff % stripe_length) + stripe_length;
        else if (startoffstripe == i)
            ctxs[i].stripe_start = startoff;
        else
            ctxs[i].stripe_start = startoff - (startoff % stripe_length);

        if (endoffstripe > i)
            ctxs[i].stripe_end = endoff - (endoff % stripe_length) + stripe_length;
        else if (endoffstripe == i)
            ctxs[i].stripe_end = endoff + 1;
        else
            ctxs[i].stripe_end = endoff - (endoff % stripe_length);
    }

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].stripe_end != ctxs[i].stripe_start) {
            ctxs[i].Irp = IoAllocateIrp(pdo->child_list[i]->device->StackSize, false);

            if (!ctxs[i].Irp) {
                ERR("IoAllocateIrp failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            PIO_STACK_LOCATION IrpSp2 = IoGetNextIrpStackLocation(ctxs[i].Irp);
            IrpSp2->MajorFunction = IRP_MJ_WRITE;

            ctxs[i].mdl = IoAllocateMdl(NULL, (ULONG)(ctxs[i].stripe_end - ctxs[i].stripe_start), false, false, NULL);
            if (!ctxs[i].mdl) {
                ERR("IoAllocateMdl failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            ctxs[i].mdl->MdlFlags |= MDL_PARTIAL;

            ctxs[i].Irp->MdlAddress = ctxs[i].mdl;

            IrpSp2->FileObject = pdo->child_list[i]->fileobj;
            IrpSp2->Parameters.Write.Length = (ULONG)(ctxs[i].stripe_end - ctxs[i].stripe_start);
            IrpSp2->Parameters.Write.ByteOffset.QuadPart = ctxs[i].stripe_start + (pdo->child_list[i]->disk_info.data_offset * 512);

            ctxs[i].Irp->UserIosb = &ctxs[i].iosb;

            KeInitializeEvent(&ctxs[i].Event, NotificationEvent, false);
            ctxs[i].Irp->UserEvent = &ctxs[i].Event;

            IoSetCompletionRoutine(ctxs[i].Irp, io_completion_raid0, &ctxs[i], true, true, true);
        } else
            ctxs[i].Status = STATUS_SUCCESS;
    }

    if (Irp->MdlAddress->ByteOffset != 0 || skip_first != 0) {
        tmpbuf = ExAllocatePoolWithTag(NonPagedPool, length, ALLOC_TAG);
        if (!tmpbuf) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        tmpmdl = IoAllocateMdl(tmpbuf, length, false, false, NULL);
        if (!tmpmdl) {
            ERR("IoAllocateMdl failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        MmBuildMdlForNonPagedPool(tmpmdl);

        PVOID src = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

        RtlCopyMemory(tmpbuf, (uint8_t*)src + skip_first, length);
    }

    {
        uint32_t pos = 0;
        uint32_t stripe = startoffstripe;
        MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

        for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
            if (ctxs[i].mdl)
                ctxs[i].pfnp = ctxs[i].pfns = MmGetMdlPfnArray(ctxs[i].mdl);
        }

        PPFN_NUMBER src_pfns = MmGetMdlPfnArray((tmpmdl ? tmpmdl : Irp->MdlAddress));

        while (pos < length) {
            uint32_t len, pages;

            if (pos == 0) {
                len = stripe_length - (startoff % stripe_length);

                if (len % PAGE_SIZE != 0) {
                    pages = len / PAGE_SIZE;
                    pages++;
                } else
                    pages = len / PAGE_SIZE;
            } else {
                len = stripe_length;
                pages = len / PAGE_SIZE;
            }

            if (pos + len > length) {
                len = length - pos;

                if (len % PAGE_SIZE != 0) {
                    pages = len / PAGE_SIZE;
                    pages++;
                } else
                    pages = len / PAGE_SIZE;
            }

            RtlCopyMemory(ctxs[stripe].pfnp, src_pfns, sizeof(PFN_NUMBER) * pages);
            src_pfns = &src_pfns[pages];
            ctxs[stripe].pfnp = &ctxs[stripe].pfnp[pages];

            pos += len;

            stripe = (stripe + 1) % pdo->array_info.raid_disks;
        }
    }

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].Irp) {
            ctxs[i].Status = IoCallDriver(pdo->child_list[i]->device, ctxs[i].Irp);
            if (!NT_SUCCESS(ctxs[i].Status))
                ERR("IoCallDriver returned %08x\n", ctxs[i].Status);
        }
    }

    if (skip_first != 0) {
        first_bit.Status = IoCallDriver(first_bit.sc->device, first_bit.Irp);
        if (!NT_SUCCESS(first_bit.Status))
            ERR("IoCallDriver returned %08x\n", first_bit.Status);
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

    if (skip_first != 0) {
        if (first_bit.Status == STATUS_PENDING) {
            KeWaitForSingleObject(&first_bit.Event, Executive, KernelMode, false, NULL);
            first_bit.Status = first_bit.iosb.Status;
        }

        if (!NT_SUCCESS(first_bit.Status))
            Status = first_bit.Status;
    }

end:
    if (!mdl_locked)
        MmUnlockPages(Irp->MdlAddress);

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].mdl)
            IoFreeMdl(ctxs[i].mdl);

        if (ctxs[i].Irp)
            IoFreeIrp(ctxs[i].Irp);
    }

    ExFreePool(ctxs);

end2:
    if (tmpmdl)
        IoFreeMdl(tmpmdl);

    if (tmpbuf)
        ExFreePool(tmpbuf);

    if (first_bit.mdl)
        IoFreeMdl(first_bit.mdl);

    if (first_bit.Irp)
        IoFreeIrp(first_bit.Irp);

    return Status;
}
