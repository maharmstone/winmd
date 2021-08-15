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

NTSTATUS __stdcall io_completion(PDEVICE_OBJECT, PIRP Irp, PVOID ctx) {
    auto context = (io_context*)ctx;

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

uint32_t set_pdo::get_parity_volume(uint64_t offset) {
    switch (array_info.level) {
        case RAID_LEVEL_4:
            return array_info.raid_disks - 1;

        case RAID_LEVEL_5:
            offset /= (array_info.raid_disks - 1) * array_info.chunksize * 512;
            offset %= array_info.raid_disks;

            if (array_info.layout == RAID_LAYOUT_RIGHT_ASYMMETRIC || array_info.layout == RAID_LAYOUT_RIGHT_SYMMETRIC)
                return (uint32_t)offset;
            else
                return array_info.raid_disks - (uint32_t)offset - 1;

        case RAID_LEVEL_6:
            offset /= (array_info.raid_disks - 2) * array_info.chunksize * 512;
            offset %= array_info.raid_disks;

            if (array_info.layout == RAID_LAYOUT_RIGHT_ASYMMETRIC || array_info.layout == RAID_LAYOUT_RIGHT_SYMMETRIC)
                return (uint32_t)offset;
            else
                return array_info.raid_disks - (uint32_t)offset - 1;

        default:
            return 0;
    }
}

uint32_t set_pdo::get_physical_stripe(uint32_t stripe, uint32_t parity) {
    if (array_info.level == RAID_LEVEL_6) {
        uint32_t q = (parity + 1) % array_info.raid_disks;

        if (array_info.layout == RAID_LAYOUT_LEFT_ASYMMETRIC || array_info.layout == RAID_LAYOUT_RIGHT_ASYMMETRIC)
            return stripe + (q == 0 ? 1 : (stripe >= parity ? 2 : 0));
        else
            return (parity + stripe + 2) % array_info.raid_disks;
    } else {
        if (array_info.level == RAID_LEVEL_5 && (array_info.layout == RAID_LAYOUT_LEFT_ASYMMETRIC || array_info.layout == RAID_LAYOUT_RIGHT_ASYMMETRIC))
            return stripe + (stripe >= parity ? 1 : 0);
        else
            return (parity + stripe + 1) % array_info.raid_disks;
    }
}

NTSTATUS set_device::read(PIRP Irp, bool* no_complete) {
    TRACE("(%p)\n", Irp);

    if (!pdo)
        return STATUS_INVALID_DEVICE_REQUEST;

    if (!pdo->loaded)
        return STATUS_DEVICE_NOT_READY;

    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->Parameters.Read.ByteOffset.QuadPart < 0) {
        WARN("read start is negative\n");
        return STATUS_INVALID_PARAMETER;
    }

    if ((uint64_t)IrpSp->Parameters.Read.ByteOffset.QuadPart >= pdo->array_size) {
        WARN("trying to read past end of device\n");
        return STATUS_INVALID_PARAMETER;
    }

    if ((uint64_t)IrpSp->Parameters.Read.ByteOffset.QuadPart + IrpSp->Parameters.Read.Length > pdo->array_size)
        IrpSp->Parameters.Read.Length = (ULONG)(pdo->array_size - IrpSp->Parameters.Read.ByteOffset.QuadPart);

    if (IrpSp->Parameters.Read.ByteOffset.QuadPart % devobj->SectorSize || IrpSp->Parameters.Read.Length % devobj->SectorSize)
        return STATUS_INVALID_PARAMETER;

    Irp->IoStatus.Information = IrpSp->Parameters.Read.Length;

    if (IrpSp->Parameters.Read.Length == 0)
        return STATUS_SUCCESS;

    switch (pdo->array_info.level) {
        case RAID_LEVEL_0:
            return read_raid0(pdo, Irp, no_complete);

        case RAID_LEVEL_1:
            return read_raid1(pdo, Irp, no_complete);

        case RAID_LEVEL_4:
        case RAID_LEVEL_5:
            return pdo->read_raid45(Irp, no_complete);

        case RAID_LEVEL_6:
            return pdo->read_raid6(Irp, no_complete);

        case RAID_LEVEL_10:
            return pdo->read_raid10(Irp, no_complete);

        case RAID_LEVEL_LINEAR:
            return read_linear(pdo, Irp, no_complete);

        default:
            return STATUS_INVALID_DEVICE_REQUEST;
    }
}

NTSTATUS device::read(PIRP, bool*) {
    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS drv_read(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    auto dev = (device*)DeviceObject->DeviceExtension;

    bool no_complete = false;

    Status = dev->read(Irp, &no_complete);

    if (!no_complete) {
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    FsRtlExitFileSystem();

    return Status;
}

NTSTATUS set_pdo::flush_partial_chunk(partial_chunk* pc) {
    NTSTATUS Status;
    LIST_ENTRY ctxs;

    TRACE("(%llx)\n", pc->offset);

    uint32_t data_disks = array_info.raid_disks - (array_info.level == RAID_LEVEL_6 ? 2 : 1);
    uint32_t chunk_size = array_info.chunksize * 512;
    bool asymmetric = array_info.layout == RAID_LAYOUT_LEFT_ASYMMETRIC || array_info.layout == RAID_LAYOUT_RIGHT_ASYMMETRIC;

    InitializeListHead(&ctxs);

    auto valid = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, sector_align(array_info.chunksize, 32) / 8, ALLOC_TAG);
    if (!valid) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RTL_BITMAP valid_bmp;

    RtlInitializeBitMap(&valid_bmp, (ULONG*)valid, array_info.chunksize);

    // FIXME - what if array_info.chunksize not multiple of 8?
    RtlCopyMemory(valid, pc->bmp.Buffer, array_info.chunksize / 8);

    for (uint32_t i = 1; i < data_disks; i++) {
        do_and(valid, (uint8_t*)pc->bmp.Buffer + (i * array_info.chunksize / 8), array_info.chunksize / 8);
    }

    {
        auto parity = get_parity_volume(pc->offset);
        uint32_t stripe = get_physical_stripe(0, parity);

        for (uint32_t i = 0; i < data_disks; i++) {
            ULONG index;
            io_context* last = nullptr;
            auto runlength = RtlFindFirstRunClear(&valid_bmp, &index);

            while (runlength != 0) {
                for (uint32_t j = index; j < index + runlength; j++) {
                    if (RtlCheckBit(&pc->bmp, (i * array_info.chunksize) + j)) {
                        uint64_t stripe_start = (pc->offset / data_disks) + (j * 512) + (child_list[stripe]->disk_info.data_offset * 512);

                        if (last && last->stripe_end == stripe_start)
                            last->stripe_end += 512;
                        else {
                            auto last = (io_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context), ALLOC_TAG);
                            if (!last) {
                                Status = STATUS_INSUFFICIENT_RESOURCES;
                                goto end;
                            }

                            new (last) io_context(child_list[stripe], stripe_start, stripe_start + 512);

                            InsertTailList(&ctxs, &last->list_entry);

                            if (!NT_SUCCESS(last->Status)) {
                                ERR("io_context constructor returned %08x\n", last->Status);
                                Status = last->Status;
                                goto end;
                            }

                            last->va2 = pc->data + (i * chunk_size) + (j * 512);
                        }
                    }
                }

                runlength = RtlFindNextForwardRunClear(&valid_bmp, index + runlength, &index);
            }

            if (asymmetric) {
                stripe++;

                if (stripe == parity) {
                    if (array_info.level == RAID_LEVEL_6)
                        stripe += 2;
                    else
                        stripe++;
                }
            } else
                stripe = (stripe + 1) % array_info.raid_disks;
        }

        if (!IsListEmpty(&ctxs)) {
            LIST_ENTRY* le = ctxs.Flink;
            while (le != &ctxs) {
                io_context* ctx = CONTAINING_RECORD(le, io_context, list_entry);

                auto IrpSp = IoGetNextIrpStackLocation(ctx->Irp);
                IrpSp->MajorFunction = IRP_MJ_READ;

                ctx->mdl = IoAllocateMdl(ctx->va2, (ULONG)(ctx->stripe_end - ctx->stripe_start), false, false, nullptr);
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
                    KeWaitForSingleObject(&ctx->Event, Executive, KernelMode, false, nullptr);
                    ctx->Status = ctx->iosb.Status;
                }

                if (!NT_SUCCESS(ctx->Status)) {
                    ERR("reading returned %08x\n", ctx->Status);
                    Status = ctx->Status;
                }

                ctx->~io_context();
                ExFreePool(ctx);
            }

            if (!NT_SUCCESS(Status))
                goto end;
        }
    }

    if (array_info.level == RAID_LEVEL_6)
        Status = flush_partial_chunk_raid6(pc, &valid_bmp);
    else
        Status = flush_partial_chunk_raid45(pc, &valid_bmp);

end:
    while (!IsListEmpty(&ctxs)) {
        io_context* ctx = CONTAINING_RECORD(RemoveHeadList(&ctxs), io_context, list_entry);

        ctx->~io_context();
        ExFreePool(ctx);
    }

    ExFreePool(valid);

    return Status;
}

void set_pdo::flush_chunks() {
    ExAcquireResourceExclusiveLite(&partial_chunks_lock, true);

    while (!IsListEmpty(&partial_chunks)) {
        auto pc = CONTAINING_RECORD(RemoveHeadList(&partial_chunks), partial_chunk, list_entry);

        flush_partial_chunk(pc);

        ExFreePool(pc);
    }

    ExReleaseResourceLite(&partial_chunks_lock);
}

void set_pdo::flush_thread() {
    LARGE_INTEGER due_time;

    ObReferenceObject(pdo);

    KeInitializeTimer(&flush_thread_timer);

    due_time.QuadPart = flush_interval * -10000000ll;

    KeSetTimer(&flush_thread_timer, due_time, nullptr);

    while (true) {
        KeWaitForSingleObject(&flush_thread_timer, Executive, KernelMode, false, nullptr);

        if (loaded)
            flush_chunks();

        if (readonly)
            break;

        KeSetTimer(&flush_thread_timer, due_time, nullptr);
    }

    ObDereferenceObject(pdo);
    KeCancelTimer(&flush_thread_timer);

    KeSetEvent(&flush_thread_finished, 0, false);

    PsTerminateSystemThread(STATUS_SUCCESS);
}

void __stdcall flush_thread(void* context) {
    auto sd = (set_pdo*)context;

    sd->flush_thread();
}

NTSTATUS set_pdo::add_partial_chunk(uint64_t offset, uint32_t length, void* data) {
    NTSTATUS Status;
    uint32_t data_disks = array_info.raid_disks - (array_info.level == RAID_LEVEL_6 ? 2 : 1);
    uint32_t full_chunk = array_info.chunksize * 512 * data_disks;
    partial_chunk* pc;
    uint32_t pclen;

    uint64_t chunk_offset = offset - (offset % full_chunk);

    ExAcquireResourceExclusiveLite(&partial_chunks_lock, true);

    LIST_ENTRY* le = partial_chunks.Flink;

    while (le != &partial_chunks) {
        auto pc = CONTAINING_RECORD(le, partial_chunk, list_entry);

        if (pc->offset == chunk_offset) {
            RtlCopyMemory(pc->data + offset - chunk_offset, data, length);

            RtlClearBits(&pc->bmp, (ULONG)((offset - chunk_offset) / 512), length / 512);

            if (RtlAreBitsClear(&pc->bmp, 0, array_info.chunksize * data_disks)) {
                NTSTATUS Status = flush_partial_chunk(pc);
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
    pclen += sector_align(array_info.chunksize * data_disks, 32) / 8; // bitmap length

    pc = (partial_chunk*)ExAllocatePoolWithTag(NonPagedPool/*FIXME - ?*/, pclen, ALLOC_TAG);
    if (!pc) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end;
    }

    pc->offset = chunk_offset;

    RtlInitializeBitMap(&pc->bmp, (ULONG*)(pc->data + full_chunk), array_info.chunksize * data_disks);
    RtlSetBits(&pc->bmp, 0, array_info.chunksize * data_disks);

    RtlCopyMemory(pc->data + offset - chunk_offset, data, length);

    RtlClearBits(&pc->bmp, (ULONG)((offset - chunk_offset) / 512), length / 512);

    InsertHeadList(le->Blink, &pc->list_entry);

    Status = STATUS_SUCCESS;

end:
    ExReleaseResourceLite(&partial_chunks_lock);

    return Status;
}

NTSTATUS set_device::write(PIRP Irp, bool* no_complete) {
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp;

    TRACE("(%p)\n", Irp);

    if (!pdo)
        return STATUS_INVALID_DEVICE_REQUEST;

    ExAcquireResourceSharedLite(&pdo->lock, true);

    if (!pdo->loaded) {
        Status = STATUS_DEVICE_NOT_READY;
        goto end;
    }

    if (pdo->readonly) {
        Status = STATUS_MEDIA_WRITE_PROTECTED;
        goto end;
    }

    IrpSp = IoGetCurrentIrpStackLocation(Irp);

    if (IrpSp->Parameters.Write.ByteOffset.QuadPart < 0) {
        WARN("write start is negative\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if ((uint64_t)IrpSp->Parameters.Write.ByteOffset.QuadPart >= pdo->array_size) {
        WARN("trying to write past end of device\n");
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    if ((uint64_t)IrpSp->Parameters.Write.ByteOffset.QuadPart + IrpSp->Parameters.Write.Length > pdo->array_size)
        IrpSp->Parameters.Write.Length = (ULONG)(pdo->array_size - IrpSp->Parameters.Write.ByteOffset.QuadPart);

    if (IrpSp->Parameters.Write.ByteOffset.QuadPart % devobj->SectorSize || IrpSp->Parameters.Write.Length % devobj->SectorSize) {
        Status = STATUS_INVALID_PARAMETER;
        goto end;
    }

    Irp->IoStatus.Information = IrpSp->Parameters.Write.Length;

    if (IrpSp->Parameters.Write.Length == 0) {
        Status = STATUS_SUCCESS;
        goto end;
    }

    switch (pdo->array_info.level) {
        case RAID_LEVEL_0:
            Status = write_raid0(pdo, Irp, no_complete);
            break;

        case RAID_LEVEL_1:
            Status = write_raid1(pdo, Irp);
            break;

        case RAID_LEVEL_4:
        case RAID_LEVEL_5:
            Status = pdo->write_raid45(Irp, no_complete);
            break;

        case RAID_LEVEL_6:
            Status = pdo->write_raid6(Irp, no_complete);
            break;

        case RAID_LEVEL_10:
            Status = pdo->write_raid10(Irp);
            break;

        case RAID_LEVEL_LINEAR:
            Status = write_linear(pdo, Irp, no_complete);
            break;

        default:
            Status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }

end:
    ExReleaseResourceLite(&pdo->lock);

    return Status;
}

NTSTATUS device::write(PIRP, bool*) {
    return STATUS_INVALID_DEVICE_REQUEST;
}

NTSTATUS drv_write(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    NTSTATUS Status;
    bool top_level;

    FsRtlEnterFileSystem();

    top_level = is_top_level(Irp);

    auto dev = (device*)DeviceObject->DeviceExtension;

    bool no_complete = false;

    Status = dev->write(Irp, &no_complete);

    if (!no_complete) {
        Irp->IoStatus.Status = Status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
    }

    if (top_level)
        IoSetTopLevelIrp(nullptr);

    FsRtlExitFileSystem();

    return Status;
}
