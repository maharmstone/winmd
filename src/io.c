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
#include <stddef.h>
#include <emmintrin.h>

static const int64_t flush_interval = 5;

typedef struct {
    PIRP Irp;
    KEVENT Event;
    IO_STATUS_BLOCK iosb;
    NTSTATUS Status;
    set_child* sc;
    uint64_t stripe_start;
    uint64_t stripe_end;
    void* va2;
    PMDL mdl;
    LIST_ENTRY list_entry;
} io_context;

_Function_class_(IO_COMPLETION_ROUTINE)
static NTSTATUS __stdcall io_completion(PDEVICE_OBJECT devobj, PIRP Irp, PVOID ctx) {
    io_context* context = ctx;

    context->iosb = Irp->IoStatus;
    KeSetEvent(&context->Event, 0, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

void do_xor(uint8_t* buf1, uint8_t* buf2, uint32_t len) {
    uint32_t j;
    __m128i x1, x2;

    if (have_sse2 && ((uintptr_t)buf1 & 0xf) == 0 && ((uintptr_t)buf2 & 0xf) == 0) {
        while (len >= 16) {
            x1 = _mm_load_si128((__m128i*)buf1);
            x2 = _mm_load_si128((__m128i*)buf2);
            x1 = _mm_xor_si128(x1, x2);
            _mm_store_si128((__m128i*)buf1, x1);

            buf1 += 16;
            buf2 += 16;
            len -= 16;
        }
    }

    while (len >= 4) {
        *(uint32_t*)buf1 ^= *(uint32_t*)buf2;
        buf1 += 4;
        buf2 += 4;
        len -= 4;
    }

    for (j = 0; j < len; j++) {
        *buf1 ^= *buf2;
        buf1++;
        buf2++;
    }
}

static void do_and(uint8_t* buf1, uint8_t* buf2, uint32_t len) {
    uint32_t j;
    __m128i x1, x2;

    if (have_sse2 && ((uintptr_t)buf1 & 0xf) == 0 && ((uintptr_t)buf2 & 0xf) == 0) {
        while (len >= 16) {
            x1 = _mm_load_si128((__m128i*)buf1);
            x2 = _mm_load_si128((__m128i*)buf2);
            x1 = _mm_and_si128(x1, x2);
            _mm_store_si128((__m128i*)buf1, x1);

            buf1 += 16;
            buf2 += 16;
            len -= 16;
        }
    }

    while (len >= 4) {
        *(uint32_t*)buf1 &= *(uint32_t*)buf2;
        buf1 += 4;
        buf2 += 4;
        len -= 4;
    }

    for (j = 0; j < len; j++) {
        *buf1 &= *buf2;
        buf1++;
        buf2++;
    }
}

uint32_t get_parity_volume(set_pdo* pdo, uint64_t offset) {
    switch (pdo->array_info.level) {
        case RAID_LEVEL_4:
            return pdo->array_info.raid_disks - 1;

        case RAID_LEVEL_5:
            offset /= (pdo->array_info.raid_disks - 1) * pdo->array_info.chunksize * 512;
            offset %= pdo->array_info.raid_disks;

            if (pdo->array_info.layout == RAID_LAYOUT_RIGHT_ASYMMETRIC || pdo->array_info.layout == RAID_LAYOUT_RIGHT_SYMMETRIC)
                return (uint32_t)offset;
            else
                return pdo->array_info.raid_disks - (uint32_t)offset - 1;

        case RAID_LEVEL_6:
            offset /= (pdo->array_info.raid_disks - 2) * pdo->array_info.chunksize * 512;
            offset %= pdo->array_info.raid_disks;

            if (pdo->array_info.layout == RAID_LAYOUT_RIGHT_ASYMMETRIC || pdo->array_info.layout == RAID_LAYOUT_RIGHT_SYMMETRIC)
                return (uint32_t)offset;
            else
                return pdo->array_info.raid_disks - (uint32_t)offset - 1;

        default:
            return 0;
    }
}

uint32_t get_physical_stripe(set_pdo* pdo, uint32_t stripe, uint32_t parity) {
    if (pdo->array_info.level == RAID_LEVEL_6) {
        uint32_t q = (parity + 1) % pdo->array_info.raid_disks;

        if (pdo->array_info.layout == RAID_LAYOUT_LEFT_ASYMMETRIC || pdo->array_info.layout == RAID_LAYOUT_RIGHT_ASYMMETRIC)
            return stripe + (q == 0 ? 1 : (stripe >= parity ? 2 : 0));
        else
            return (parity + stripe + 2) % pdo->array_info.raid_disks;
    } else {
        if (pdo->array_info.level == RAID_LEVEL_5 && (pdo->array_info.layout == RAID_LAYOUT_LEFT_ASYMMETRIC || pdo->array_info.layout == RAID_LAYOUT_RIGHT_ASYMMETRIC))
            return stripe + (stripe >= parity ? 1 : 0);
        else
            return (parity + stripe + 1) % pdo->array_info.raid_disks;
    }
}

static NTSTATUS set_read(set_device* set, PIRP Irp, bool* no_complete) {
    TRACE("(%p, %p)\n", set, Irp);

    if (!set->pdo)
        return STATUS_INVALID_DEVICE_REQUEST;

    if (!set->pdo->loaded)
        return STATUS_DEVICE_NOT_READY;

    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->Parameters.Read.ByteOffset.QuadPart < 0) {
        WARN("read start is negative\n");
        return STATUS_INVALID_PARAMETER;
    }

    if ((uint64_t)IrpSp->Parameters.Read.ByteOffset.QuadPart >= set->pdo->array_size) {
        WARN("trying to read past end of device\n");
        return STATUS_INVALID_PARAMETER;
    }

    if ((uint64_t)IrpSp->Parameters.Read.ByteOffset.QuadPart + IrpSp->Parameters.Read.Length > set->pdo->array_size)
        IrpSp->Parameters.Read.Length = (ULONG)(set->pdo->array_size - IrpSp->Parameters.Read.ByteOffset.QuadPart);

    if (IrpSp->Parameters.Read.ByteOffset.QuadPart % set->devobj->SectorSize || IrpSp->Parameters.Read.Length % set->devobj->SectorSize)
        return STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Information = IrpSp->Parameters.Read.Length;

    if (IrpSp->Parameters.Read.Length == 0)
        return STATUS_SUCCESS;

    switch (set->pdo->array_info.level) {
        case RAID_LEVEL_0:
            return read_raid0(set->pdo, Irp, no_complete);

        case RAID_LEVEL_1:
            return read_raid1(set->pdo, Irp, no_complete);

        case RAID_LEVEL_4:
        case RAID_LEVEL_5:
            return read_raid45(set->pdo, Irp, no_complete);

        case RAID_LEVEL_6:
            return read_raid6(set->pdo, Irp, no_complete);

        case RAID_LEVEL_10:
            return read_raid10(set->pdo, Irp, no_complete);

        case RAID_LEVEL_LINEAR:
            return read_linear(set->pdo, Irp, no_complete);

        default:
            return STATUS_INVALID_DEVICE_REQUEST;
    }
}

_Dispatch_type_(IRP_MJ_READ)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS drv_read(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    bool no_complete = false;

    switch (*(enum device_type*)DeviceObject->DeviceExtension) {
        case device_type_set:
            Status = set_read((set_device*)(DeviceObject->DeviceExtension), Irp, &no_complete);
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
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

static NTSTATUS flush_partial_chunk(set_pdo* pdo, partial_chunk* pc) {
    NTSTATUS Status;
    LIST_ENTRY ctxs;

    TRACE("(%llx)\n", pc->offset);

    uint32_t data_disks = pdo->array_info.raid_disks - (pdo->array_info.level == RAID_LEVEL_6 ? 2 : 1);
    uint32_t chunk_size = pdo->array_info.chunksize * 512;
    bool asymmetric = pdo->array_info.layout == RAID_LAYOUT_LEFT_ASYMMETRIC || pdo->array_info.layout == RAID_LAYOUT_RIGHT_ASYMMETRIC;

    InitializeListHead(&ctxs);

    uint8_t* valid = ExAllocatePoolWithTag(NonPagedPool, sector_align32(pdo->array_info.chunksize, 32) / 8, ALLOC_TAG);
    if (!valid) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RTL_BITMAP valid_bmp;

    RtlInitializeBitMap(&valid_bmp, (ULONG*)valid, pdo->array_info.chunksize);

    // FIXME - what if array_info.chunksize not multiple of 8?
    RtlCopyMemory(valid, pc->bmp.Buffer, pdo->array_info.chunksize / 8);

    for (uint32_t i = 1; i < data_disks; i++) {
        do_and(valid, (uint8_t*)pc->bmp.Buffer + (i * pdo->array_info.chunksize / 8), pdo->array_info.chunksize / 8);
    }

    {
        uint32_t parity = get_parity_volume(pdo, pc->offset);
        uint32_t stripe = get_physical_stripe(pdo, 0, parity);

        for (uint32_t i = 0; i < data_disks; i++) {
            ULONG index;
            io_context* last = NULL;
            ULONG runlength = RtlFindFirstRunClear(&valid_bmp, &index);

            while (runlength != 0) {
                for (uint32_t j = index; j < index + runlength; j++) {
                    if (RtlCheckBit(&pc->bmp, (i * pdo->array_info.chunksize) + j)) {
                        uint64_t stripe_start = (pc->offset / data_disks) + (j * 512) + (pdo->child_list[stripe]->disk_info.data_offset * 512);

                        if (last && last->stripe_end == stripe_start)
                            last->stripe_end += 512;
                        else {
                            io_context* last = ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context), ALLOC_TAG);
                            if (!last) {
                                Status = STATUS_INSUFFICIENT_RESOURCES;
                                goto end;
                            }

                            last->sc = pdo->child_list[stripe];
                            last->stripe_start = stripe_start;
                            last->stripe_end = stripe_start + 512;

                            last->Irp = IoAllocateIrp(pdo->child_list[stripe]->device->StackSize, false);
                            if (!last->Irp) {
                                ERR("out of memory\n");
                                ExFreePool(last);
                                Status = STATUS_INSUFFICIENT_RESOURCES;
                                goto end;
                            }

                            last->Irp->UserIosb = &last->iosb;

                            KeInitializeEvent(&last->Event, NotificationEvent, false);
                            last->Irp->UserEvent = &last->Event;

                            IoSetCompletionRoutine(last->Irp, io_completion, last, true, true, true);

                            last->Status = STATUS_SUCCESS;

                            last->mdl = NULL;

                            InsertTailList(&ctxs, &last->list_entry);

                            last->va2 = pc->data + (i * chunk_size) + (j * 512);
                        }
                    }
                }

                runlength = RtlFindNextForwardRunClear(&valid_bmp, index + runlength, &index);
            }

            if (asymmetric) {
                stripe++;

                if (stripe == parity) {
                    if (pdo->array_info.level == RAID_LEVEL_6)
                        stripe += 2;
                    else
                        stripe++;
                }
            } else
                stripe = (stripe + 1) % pdo->array_info.raid_disks;
        }

        if (!IsListEmpty(&ctxs)) {
            LIST_ENTRY* le = ctxs.Flink;
            while (le != &ctxs) {
                io_context* ctx = CONTAINING_RECORD(le, io_context, list_entry);

                PIO_STACK_LOCATION IrpSp = IoGetNextIrpStackLocation(ctx->Irp);
                IrpSp->MajorFunction = IRP_MJ_READ;

                ctx->mdl = IoAllocateMdl(ctx->va2, (ULONG)(ctx->stripe_end - ctx->stripe_start), false, false, NULL);
                if (!ctx->mdl) {
                    ERR("IoAllocateMdl failed\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }

                MmBuildMdlForNonPagedPool(ctx->mdl);

                ctx->Irp->MdlAddress = ctx->mdl;

                IrpSp->FileObject = ctx->sc->fileobj;
                IrpSp->Parameters.Read.ByteOffset.QuadPart = ctx->stripe_start;
                IrpSp->Parameters.Read.Length = (ULONG)(ctx->stripe_end - ctx->stripe_start);

                ctx->Status = IoCallDriver(ctx->sc->device, ctx->Irp);

                le = le->Flink;
            }

            Status = STATUS_SUCCESS;

            while (!IsListEmpty(&ctxs)) {
                io_context* ctx = CONTAINING_RECORD(RemoveHeadList(&ctxs), io_context, list_entry);

                if (ctx->Status == STATUS_PENDING) {
                    KeWaitForSingleObject(&ctx->Event, Executive, KernelMode, false, NULL);
                    ctx->Status = ctx->iosb.Status;
                }

                if (!NT_SUCCESS(ctx->Status)) {
                    ERR("reading returned %08x\n", ctx->Status);
                    Status = ctx->Status;
                }

                if (ctx->mdl)
                    IoFreeMdl(ctx->mdl);

                if (ctx->Irp)
                    IoFreeIrp(ctx->Irp);

                ExFreePool(ctx);
            }

            if (!NT_SUCCESS(Status))
                goto end;
        }
    }

    if (pdo->array_info.level == RAID_LEVEL_6)
        Status = flush_partial_chunk_raid6(pdo, pc, &valid_bmp);
    else
        Status = flush_partial_chunk_raid45(pdo, pc, &valid_bmp);

end:
    while (!IsListEmpty(&ctxs)) {
        io_context* ctx = CONTAINING_RECORD(RemoveHeadList(&ctxs), io_context, list_entry);

        if (ctx->mdl)
            IoFreeMdl(ctx->mdl);

        if (ctx->Irp)
            IoFreeIrp(ctx->Irp);

        ExFreePool(ctx);
    }

    ExFreePool(valid);

    return Status;
}

void flush_chunks(set_pdo* pdo) {
    ExAcquireResourceExclusiveLite(&pdo->partial_chunks_lock, true);

    while (!IsListEmpty(&pdo->partial_chunks)) {
        partial_chunk* pc = CONTAINING_RECORD(RemoveHeadList(&pdo->partial_chunks), partial_chunk, list_entry);

        flush_partial_chunk(pdo, pc);

        ExFreePool(pc);
    }

    ExReleaseResourceLite(&pdo->partial_chunks_lock);
}

_Function_class_(KSTART_ROUTINE)
void __stdcall flush_thread(void* context) {
    set_pdo* sd = (set_pdo*)context;

    LARGE_INTEGER due_time;

    ObReferenceObject(sd->pdo);

    KeInitializeTimer(&sd->flush_thread_timer);

    due_time.QuadPart = flush_interval * -10000000ll;

    KeSetTimer(&sd->flush_thread_timer, due_time, NULL);

    while (true) {
        KeWaitForSingleObject(&sd->flush_thread_timer, Executive, KernelMode, false, NULL);

        if (sd->loaded)
            flush_chunks(sd);

        if (sd->readonly)
            break;

        KeSetTimer(&sd->flush_thread_timer, due_time, NULL);
    }

    ObDereferenceObject(sd->pdo);
    KeCancelTimer(&sd->flush_thread_timer);

    KeSetEvent(&sd->flush_thread_finished, 0, false);

    PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS add_partial_chunk(set_pdo* pdo, uint64_t offset, uint32_t length, void* data) {
    NTSTATUS Status;
    uint32_t data_disks = pdo->array_info.raid_disks - (pdo->array_info.level == RAID_LEVEL_6 ? 2 : 1);
    uint32_t full_chunk = pdo->array_info.chunksize * 512 * data_disks;
    partial_chunk* pc;
    uint32_t pclen;

    uint64_t chunk_offset = offset - (offset % full_chunk);

    ExAcquireResourceExclusiveLite(&pdo->partial_chunks_lock, true);

    LIST_ENTRY* le = pdo->partial_chunks.Flink;

    while (le != &pdo->partial_chunks) {
        partial_chunk* pc = CONTAINING_RECORD(le, partial_chunk, list_entry);

        if (pc->offset == chunk_offset) {
            RtlCopyMemory(pc->data + offset - chunk_offset, data, length);

            RtlClearBits(&pc->bmp, (ULONG)((offset - chunk_offset) / 512), length / 512);

            if (RtlAreBitsClear(&pc->bmp, 0, pdo->array_info.chunksize * data_disks)) {
                Status = flush_partial_chunk(pdo, pc);
                if (!NT_SUCCESS(Status)) {
                    ERR("flush_partial_chunk returned %08x\n", Status);
                    goto end;
                }

                RemoveEntryList(&pc->list_entry);
                ExFreePool(pc);
            }

            Status = STATUS_SUCCESS;
            goto end;
        } else if (pc->offset > chunk_offset)
            break;

        le = le->Flink;
    }

    pclen = offsetof(partial_chunk, data[0]);
    pclen += full_chunk; // data length
    pclen += sector_align32(pdo->array_info.chunksize * data_disks, 32) / 8; // bitmap length

    pc = ExAllocatePoolWithTag(NonPagedPool/*FIXME - ?*/, pclen, ALLOC_TAG);
    if (!pc) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    pc->offset = chunk_offset;

    RtlInitializeBitMap(&pc->bmp, (ULONG*)(pc->data + full_chunk), pdo->array_info.chunksize * data_disks);
    RtlSetBits(&pc->bmp, 0, pdo->array_info.chunksize * data_disks);

    RtlCopyMemory(pc->data + offset - chunk_offset, data, length);

    RtlClearBits(&pc->bmp, (ULONG)((offset - chunk_offset) / 512), length / 512);

    InsertHeadList(le->Blink, &pc->list_entry);

    Status = STATUS_SUCCESS;

end:
    ExReleaseResourceLite(&pdo->partial_chunks_lock);

    return Status;
}

static NTSTATUS set_write(set_device* set, PIRP Irp, bool* no_complete) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp;

    TRACE("(%p, %p)\n", set, Irp);

    if (!set->pdo)
        return STATUS_INVALID_DEVICE_REQUEST;

    ExAcquireResourceSharedLite(&set->pdo->lock, true);

    if (!set->pdo->loaded) {
        Status = STATUS_DEVICE_NOT_READY;
        goto end;
    }

    if (set->pdo->readonly) {
        Status = STATUS_MEDIA_WRITE_PROTECTED;
        goto end;
    }

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->Parameters.Write.ByteOffset.QuadPart < 0) {
        WARN("write start is negative\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if ((uint64_t)IrpSp->Parameters.Write.ByteOffset.QuadPart >= set->pdo->array_size) {
        WARN("trying to write past end of device\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if ((uint64_t)IrpSp->Parameters.Write.ByteOffset.QuadPart + IrpSp->Parameters.Write.Length > set->pdo->array_size)
        IrpSp->Parameters.Write.Length = (ULONG)(set->pdo->array_size - IrpSp->Parameters.Write.ByteOffset.QuadPart);

    if (IrpSp->Parameters.Write.ByteOffset.QuadPart % set->devobj->SectorSize || IrpSp->Parameters.Write.Length % set->devobj->SectorSize) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    Irp->IoStatus.Information = IrpSp->Parameters.Write.Length;

    if (IrpSp->Parameters.Write.Length == 0) {
        Status = STATUS_SUCCESS;
        goto end;
    }

    switch (set->pdo->array_info.level) {
        case RAID_LEVEL_0:
            Status = write_raid0(set->pdo, Irp, no_complete);
            break;

        case RAID_LEVEL_1:
            Status = write_raid1(set->pdo, Irp);
            break;

        case RAID_LEVEL_4:
        case RAID_LEVEL_5:
            Status = write_raid45(set->pdo, Irp, no_complete);
            break;

        case RAID_LEVEL_6:
            Status = write_raid6(set->pdo, Irp, no_complete);
            break;

        case RAID_LEVEL_10:
            Status = write_raid10(set->pdo, Irp);
            break;

        case RAID_LEVEL_LINEAR:
            Status = write_linear(set->pdo, Irp, no_complete);
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

end:
    ExReleaseResourceLite(&set->pdo->lock);

    return Status;
}

_Dispatch_type_(IRP_MJ_WRITE)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS drv_write(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    bool no_complete = false;

    switch (*(enum device_type*)DeviceObject->DeviceExtension) {
        case device_type_set:
            Status = set_write((set_device*)(DeviceObject->DeviceExtension), Irp, &no_complete);
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
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
