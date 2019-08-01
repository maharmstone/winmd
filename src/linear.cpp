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

NTSTATUS set_pdo::io_linear2(PIRP Irp, uint64_t offset, uint32_t start_disk, bool write) {
    NTSTATUS Status;
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);
    uint32_t length = write ? IrpSp->Parameters.Write.Length : IrpSp->Parameters.Read.Length;
    klist<io_context> ctxs;
    auto va = (uint8_t*)MmGetMdlVirtualAddress(Irp->MdlAddress);

    for (uint32_t i = start_disk; i < array_info.raid_disks; i++) {
        auto io_length = (uint32_t)min(length, (child_list[i]->disk_info.data_size * 512) - offset);

        ctxs.emplace_back_np(child_list[i], offset + (child_list[i]->disk_info.data_offset * 512), io_length);
        auto& last = ctxs.back();

        if (!NT_SUCCESS(last.Status)) {
            ERR("io_context constructor returned %08x\n", last.Status);
            return last.Status;
        }

        last.mdl = IoAllocateMdl(va, io_length, false, false, nullptr);
        if (!last.mdl) {
            ERR("IoAllocateMdl failed\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        last.Irp->MdlAddress = last.mdl;

        IoBuildPartialMdl(Irp->MdlAddress, last.mdl, va, io_length);

        auto IrpSp2 = IoGetNextIrpStackLocation(last.Irp);

        IrpSp2->FileObject = child_list[i]->fileobj;

        if (write) {
            IrpSp2->MajorFunction = IRP_MJ_WRITE;
            IrpSp2->Parameters.Write.ByteOffset.QuadPart = offset + (child_list[i]->disk_info.data_offset * 512);
            IrpSp2->Parameters.Write.Length = io_length;
        } else {
            IrpSp2->MajorFunction = IRP_MJ_READ;
            IrpSp2->Parameters.Read.ByteOffset.QuadPart = offset + (child_list[i]->disk_info.data_offset * 512);
            IrpSp2->Parameters.Read.Length = io_length;
        }

        last.Status = IoCallDriver(last.sc->device, last.Irp);

        length -= io_length;

        if (length == 0)
            break;

        offset = 0;
        va += io_length;
    }

    Status = STATUS_SUCCESS;

    LIST_ENTRY* le = ctxs.list.Flink;
    while (le != &ctxs.list) {
        auto& ctx = ctxs.entry(le);

        if (ctx.Status == STATUS_PENDING) {
            KeWaitForSingleObject(&ctx.Event, Executive, KernelMode, false, nullptr);
            ctx.Status = ctx.iosb.Status;
        }

        if (!NT_SUCCESS(ctx.Status)) {
            ERR("device returned %08x\n", ctx.Status);
            Status = ctx.Status;
        }

        le = le->Flink;
    }

    return Status;
}

NTSTATUS set_pdo::read_linear(PIRP Irp, bool* no_complete) {
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);
    uint64_t offset = IrpSp->Parameters.Read.ByteOffset.QuadPart;
    uint32_t length = IrpSp->Parameters.Read.Length;

    shared_eresource l(&lock);

    for (uint32_t i = 0; i < array_info.raid_disks; i++) {
        if (offset < (child_list[i]->disk_info.data_size * 512)) {
            if (offset + length < (child_list[i]->disk_info.data_size * 512) || i == array_info.raid_disks - 1) {
                auto c = child_list[i];

                IoCopyCurrentIrpStackLocationToNext(Irp);

                auto IrpSp2 = IoGetNextIrpStackLocation(Irp);

                IrpSp2->FileObject = child_list[i]->fileobj;
                IrpSp2->Parameters.Read.ByteOffset.QuadPart = offset + (c->disk_info.data_offset * 512);

                if (i == array_info.raid_disks - 1)
                    IrpSp2->Parameters.Read.Length = (uint32_t)min(IrpSp2->Parameters.Read.Length, ((child_list[i]->disk_info.data_size * 512) - offset));

                *no_complete = true;

                return IoCallDriver(c->device, Irp);
            } else
                return io_linear2(Irp, offset, i, false);
        }

        offset -= child_list[i]->disk_info.data_size * 512;
    }

    return STATUS_INVALID_PARAMETER;
}

NTSTATUS set_pdo::write_linear(PIRP Irp, bool* no_complete) {
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);
    uint64_t offset = IrpSp->Parameters.Write.ByteOffset.QuadPart;
    uint32_t length = IrpSp->Parameters.Write.Length;

    for (uint32_t i = 0; i < array_info.raid_disks; i++) {
        if (offset < (child_list[i]->disk_info.data_size * 512)) {
            if (offset + length < (child_list[i]->disk_info.data_size * 512) || i == array_info.raid_disks - 1) {
                auto c = child_list[i];

                IoCopyCurrentIrpStackLocationToNext(Irp);

                auto IrpSp2 = IoGetNextIrpStackLocation(Irp);

                IrpSp2->FileObject = child_list[i]->fileobj;
                IrpSp2->Parameters.Write.ByteOffset.QuadPart = offset + (c->disk_info.data_offset * 512);

                if (i == array_info.raid_disks - 1)
                    IrpSp2->Parameters.Write.Length = (uint32_t)min(IrpSp2->Parameters.Write.Length, ((child_list[i]->disk_info.data_size * 512) - offset));

                *no_complete = true;

                return IoCallDriver(c->device, Irp);
            } else
                return io_linear2(Irp, offset, i, true);
        }

        offset -= child_list[i]->disk_info.data_size * 512;
    }

    return STATUS_INVALID_PARAMETER;
}
