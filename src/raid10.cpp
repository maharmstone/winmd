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

static NTSTATUS read_raid10_odd(set_pdo* pdo, PIRP Irp, bool* no_complete) {
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);
    bool mdl_locked = true;
    uint8_t near = pdo->array_info.layout & 0xff;
    uint32_t stripe_length = pdo->array_info.chunksize * 512;
    uint64_t offset = IrpSp->Parameters.Read.ByteOffset.QuadPart;
    uint32_t length = IrpSp->Parameters.Read.Length;
    uint64_t start_chunk = offset / stripe_length;
    uint64_t end_chunk = (offset + length - 1) / stripe_length;
    void* dummypage = nullptr;
    PMDL dummy_mdl = nullptr;
    PFN_NUMBER dummy;
    uint8_t* tmpbuf = nullptr;
    PMDL tmpmdl = nullptr;

    if (start_chunk == end_chunk) { // small reads, on one device
        uint64_t chunk = (start_chunk * near) + (pdo->read_device % near);
        auto c = pdo->child_list[chunk % pdo->array_info.raid_disks];

        IoCopyCurrentIrpStackLocationToNext(Irp);

        auto IrpSp2 = IoGetNextIrpStackLocation(Irp);

        uint64_t start = (chunk / pdo->array_info.raid_disks) * stripe_length;

        start += offset % stripe_length;
        start += c->disk_info.data_offset * 512;

        IrpSp2->FileObject = c->fileobj;
        IrpSp2->Parameters.Read.ByteOffset.QuadPart = start;

        *no_complete = true;

        return IoCallDriver(c->device, Irp);
    }

    uint32_t skip_first = offset % PAGE_SIZE;

    offset -= skip_first;
    length += skip_first;

    auto ctxs = (io_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context) * pdo->array_info.raid_disks, ALLOC_TAG);
    if (!ctxs) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ctxs, sizeof(io_context) * pdo->array_info.raid_disks);

    {
        uint64_t chunk = (start_chunk * near) + (pdo->read_device % near);
        uint32_t pos = 0;

        while (pos < length) {
            uint32_t disk_num = chunk % pdo->array_info.raid_disks;

            if (pos == 0) {
                ctxs[disk_num].stripe_start = (chunk / pdo->array_info.raid_disks) * stripe_length;
                ctxs[disk_num].stripe_start += offset % stripe_length;

                uint32_t len = min(length, stripe_length - offset % stripe_length);

                ctxs[disk_num].stripe_end = ctxs[disk_num].stripe_start + len;

                pos += len;
            } else {
                uint32_t len = min(length - pos, stripe_length);

                if (ctxs[disk_num].stripe_start == 0)
                    ctxs[disk_num].stripe_start = (chunk / pdo->array_info.raid_disks) * stripe_length;

                ctxs[disk_num].stripe_end = ((chunk / pdo->array_info.raid_disks) * stripe_length) + len;

                pos += len;
            }

            chunk += near;
        }
    }

    NTSTATUS Status;

    {
        dummypage = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, ALLOC_TAG);
        if (!dummypage) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        dummy_mdl = IoAllocateMdl(dummypage, PAGE_SIZE, FALSE, FALSE, NULL);
        if (!dummy_mdl) {
            ERR("IoAllocateMdl failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        MmBuildMdlForNonPagedPool(dummy_mdl);

        dummy = *(PFN_NUMBER*)(dummy_mdl + 1);
    }

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].stripe_end != ctxs[i].stripe_start) {
            ctxs[i].Irp = IoAllocateIrp(pdo->child_list[i]->device->StackSize, false);

            if (!ctxs[i].Irp) {
                ERR("IoAllocateIrp failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            auto IrpSp2 = IoGetNextIrpStackLocation(ctxs[i].Irp);
            IrpSp2->MajorFunction = IRP_MJ_READ;

            ctxs[i].mdl = IoAllocateMdl(nullptr, (ULONG)(ctxs[i].stripe_end - ctxs[i].stripe_start), false, false, nullptr);
            if (!ctxs[i].mdl) {
                ERR("IoAllocateMdl failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            ctxs[i].mdl->MdlFlags |= MDL_PARTIAL;

            ctxs[i].Irp->MdlAddress = ctxs[i].mdl;

            {
                auto pfns = MmGetMdlPfnArray(ctxs[i].mdl);

                uint32_t pages = sector_align((uint32_t)(ctxs[i].stripe_end - ctxs[i].stripe_start), PAGE_SIZE) / PAGE_SIZE;

                for (uint32_t j = 0; j < pages; j++) {
                    pfns[j] = dummy;
                }
            }

            IrpSp2->FileObject = pdo->child_list[i]->fileobj;
            IrpSp2->Parameters.Read.Length = (ULONG)(ctxs[i].stripe_end - ctxs[i].stripe_start);
            IrpSp2->Parameters.Read.ByteOffset.QuadPart = ctxs[i].stripe_start + (pdo->child_list[i]->disk_info.data_offset * 512);

            ctxs[i].Irp->UserIosb = &ctxs[i].iosb;

            KeInitializeEvent(&ctxs[i].Event, NotificationEvent, false);
            ctxs[i].Irp->UserEvent = &ctxs[i].Event;

            IoSetCompletionRoutine(ctxs[i].Irp, io_completion, &ctxs[i], true, true, true);
        } else
            ctxs[i].Status = STATUS_SUCCESS;
    }

    mdl_locked = Irp->MdlAddress->MdlFlags & (MDL_PAGES_LOCKED | MDL_PARTIAL);

    if (!mdl_locked) {
        Status = STATUS_SUCCESS;

        seh_try {
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoWriteAccess);
        } seh_except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (!NT_SUCCESS(Status)) {
            ERR("MmProbeAndLockPages threw exception %08x\n", Status);
            mdl_locked = true;
            goto end;
        }
    }

    if (Irp->MdlAddress->ByteOffset != 0 || skip_first != 0) {
        tmpbuf = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, length, ALLOC_TAG);
        if (!tmpbuf) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        tmpmdl = IoAllocateMdl(tmpbuf, length, false, false, nullptr);
        if (!tmpmdl) {
            ERR("IoAllocateMdl failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        MmBuildMdlForNonPagedPool(tmpmdl);
    }

    {
        uint64_t chunk = (start_chunk * near) + (pdo->read_device % near);
        uint32_t pos = 0;
        MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

        for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
            if (ctxs[i].mdl) {
                ctxs[i].pfns = MmGetMdlPfnArray(ctxs[i].mdl);
                ctxs[i].stripe_pos = ctxs[i].stripe_start - (ctxs[i].stripe_start % stripe_length);
            }
        }

        auto src_pfns = MmGetMdlPfnArray((tmpmdl ? tmpmdl : Irp->MdlAddress));

        while (pos < length) {
            uint32_t disk_num = chunk % pdo->array_info.raid_disks;
            uint32_t len, pages;
            uint64_t ss = (chunk / pdo->array_info.raid_disks) * stripe_length;

            if (pos == 0) {
                len = min(length, stripe_length - (offset % stripe_length));

                if (len % PAGE_SIZE != 0) {
                    pages = len / PAGE_SIZE;
                    pages++;
                } else
                    pages = len / PAGE_SIZE;

                RtlCopyMemory(ctxs[disk_num].pfns, src_pfns, sizeof(PFN_NUMBER) * pages);
                src_pfns = &src_pfns[pages];
            } else {
                if (length < pos + stripe_length) {
                    len = length - pos;

                    if (len % PAGE_SIZE != 0) {
                        pages = len / PAGE_SIZE;
                        pages++;
                    } else
                        pages = len / PAGE_SIZE;
                } else {
                    len = stripe_length;
                    pages = len / PAGE_SIZE;
                }

                RtlCopyMemory(&ctxs[disk_num].pfns[(ss - ctxs[disk_num].stripe_pos) / PAGE_SIZE], src_pfns, sizeof(PFN_NUMBER) * pages);
                src_pfns = &src_pfns[pages];
            }

            pos += len;
            chunk += near;
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
            KeWaitForSingleObject(&ctxs[i].Event, Executive, KernelMode, false, nullptr);
            ctxs[i].Status = ctxs[i].iosb.Status;
        }

        if (!NT_SUCCESS(ctxs[i].Status))
            Status = ctxs[i].Status;
    }

    if (tmpbuf) {
        auto dest = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

        RtlCopyMemory(dest, tmpbuf + skip_first, length - skip_first);
    }

end:
    if (!mdl_locked)
        MmUnlockPages(Irp->MdlAddress);

    if (dummy_mdl)
        IoFreeMdl(dummy_mdl);

    if (dummypage)
        ExFreePool(dummypage);

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

static NTSTATUS read_raid10_offset(set_pdo* pdo, PIRP Irp, bool* no_complete) {
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);
    bool mdl_locked = true;
    uint8_t far = (pdo->array_info.layout >> 8) & 0xff;
    uint64_t offset = IrpSp->Parameters.Read.ByteOffset.QuadPart;
    uint32_t length = IrpSp->Parameters.Read.Length;
    uint32_t stripe_length = pdo->array_info.chunksize * 512;
    uint64_t start_chunk = offset / stripe_length;
    uint64_t end_chunk = (offset + length - 1) / stripe_length;
    void* dummypage = nullptr;
    PMDL dummy_mdl = nullptr;
    uint8_t far_offset = pdo->read_device % far;

    if (start_chunk == end_chunk) { // small reads, on one device
        uint64_t start = (((start_chunk / pdo->array_info.raid_disks) * far) + far_offset) * stripe_length;
        auto c = pdo->child_list[(start_chunk + far_offset) % pdo->array_info.raid_disks];

        IoCopyCurrentIrpStackLocationToNext(Irp);

        auto IrpSp2 = IoGetNextIrpStackLocation(Irp);

        start += offset % stripe_length;
        start += c->disk_info.data_offset * 512;

        IrpSp2->FileObject = c->fileobj;
        IrpSp2->Parameters.Read.ByteOffset.QuadPart = start;

        *no_complete = true;

        return IoCallDriver(c->device, Irp);
    }

    uint32_t skip_first = offset % PAGE_SIZE;

    offset -= skip_first;
    length += skip_first;

    uint64_t startoff, endoff;
    uint32_t startoffstripe, endoffstripe;
    uint8_t* tmpbuf = nullptr;
    PMDL tmpmdl = nullptr;

    get_raid0_offset(offset, stripe_length, pdo->array_info.raid_disks, &startoff, &startoffstripe);
    get_raid0_offset(offset + length - 1, stripe_length, pdo->array_info.raid_disks, &endoff, &endoffstripe);

    auto ctxs = (io_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context) * pdo->array_info.raid_disks, ALLOC_TAG);
    if (!ctxs) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ctxs, sizeof(io_context) * pdo->array_info.raid_disks);

    bool need_dummy = false;

    uint32_t pos = 0;
    while (pos < length) {
        if (pos == 0) {
            for (uint32_t i = startoffstripe; i < pdo->array_info.raid_disks; i++) {
                uint32_t readlen;

                if (i == startoffstripe) {
                    readlen = min(length, (uint32_t)(stripe_length - (startoff % stripe_length)));

                    ctxs[i].stripe_start = ((startoff - (startoff % stripe_length)) * far) + (startoff % stripe_length);
                } else {
                    readlen = min(length - pos, (uint32_t)stripe_length);

                    ctxs[i].stripe_start = (startoff - (startoff % stripe_length)) * far;
                }

                ctxs[i].stripe_end = ctxs[i].stripe_start + readlen;

                pos += readlen;

                if (pos == length)
                    break;
            }

            if (pos == length)
                break;

            for (uint32_t i = 0; i < startoffstripe; i++) {
                ctxs[i].stripe_start = ctxs[i].stripe_end = far * ((startoff - (startoff % stripe_length)) + stripe_length);
            }

            if (length - pos > pdo->array_info.raid_disks * stripe_length) {
                auto skip = (uint32_t)(((length - pos) / (pdo->array_info.raid_disks * stripe_length)) - 1);

                for (uint32_t i = 0; i < pdo->array_info.raid_disks; i++) {
                    ctxs[i].stripe_end += skip * far * stripe_length;
                }

                pos += (uint32_t)(skip * pdo->array_info.raid_disks * stripe_length);
                need_dummy = true;
            }
        } else if (length - pos >= stripe_length * pdo->array_info.raid_disks) {
            for (uint32_t i = 0; i < pdo->array_info.raid_disks; i++) {
                ctxs[i].stripe_end += far * stripe_length;
            }

            pos += (uint32_t)(stripe_length * pdo->array_info.raid_disks);
            need_dummy = true;
        } else {
            for (uint32_t i = 0; i < pdo->array_info.raid_disks; i++) {
                if (endoffstripe == i) {
                    ctxs[i].stripe_end = ((endoff - (endoff % stripe_length)) * far) + (endoff % stripe_length) + 1;
                    break;
                } else if (endoffstripe > i)
                    ctxs[i].stripe_end = ((endoff - (endoff % stripe_length)) * far) + stripe_length;
            }

            break;
        }
    }

    NTSTATUS Status;

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].stripe_end != ctxs[i].stripe_start) {
            auto c = pdo->child_list[(i + far_offset) % pdo->array_info.raid_disks];

            ctxs[i].Irp = IoAllocateIrp(c->device->StackSize, false);

            if (!ctxs[i].Irp) {
                ERR("IoAllocateIrp failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            auto IrpSp2 = IoGetNextIrpStackLocation(ctxs[i].Irp);
            IrpSp2->MajorFunction = IRP_MJ_READ;

            ctxs[i].mdl = IoAllocateMdl(nullptr, (ULONG)(ctxs[i].stripe_end - ctxs[i].stripe_start), false, false, nullptr);
            if (!ctxs[i].mdl) {
                ERR("IoAllocateMdl failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            ctxs[i].mdl->MdlFlags |= MDL_PARTIAL;

            ctxs[i].Irp->MdlAddress = ctxs[i].mdl;
            ctxs[i].sc = c;

            IrpSp2->FileObject = c->fileobj;
            IrpSp2->Parameters.Read.Length = (ULONG)(ctxs[i].stripe_end - ctxs[i].stripe_start);

            IrpSp2->Parameters.Read.ByteOffset.QuadPart = ctxs[i].stripe_start;
            IrpSp2->Parameters.Read.ByteOffset.QuadPart += far_offset * stripe_length;
            IrpSp2->Parameters.Read.ByteOffset.QuadPart += c->disk_info.data_offset * 512;

            ctxs[i].Irp->UserIosb = &ctxs[i].iosb;

            KeInitializeEvent(&ctxs[i].Event, NotificationEvent, false);
            ctxs[i].Irp->UserEvent = &ctxs[i].Event;

            IoSetCompletionRoutine(ctxs[i].Irp, io_completion, &ctxs[i], true, true, true);
        } else
            ctxs[i].Status = STATUS_SUCCESS;
    }

    mdl_locked = Irp->MdlAddress->MdlFlags & (MDL_PAGES_LOCKED | MDL_PARTIAL);

    if (!mdl_locked) {
        Status = STATUS_SUCCESS;

        seh_try {
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoWriteAccess);
        } seh_except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (!NT_SUCCESS(Status)) {
            ERR("MmProbeAndLockPages threw exception %08x\n", Status);
            mdl_locked = true;
            goto end;
        }
    }

    if (Irp->MdlAddress->ByteOffset != 0 || skip_first != 0) {
        tmpbuf = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, length, ALLOC_TAG);
        if (!tmpbuf) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        tmpmdl = IoAllocateMdl(tmpbuf, length, false, false, nullptr);
        if (!tmpmdl) {
            ERR("IoAllocateMdl failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        MmBuildMdlForNonPagedPool(tmpmdl);
    }

    {
        PFN_NUMBER dummy;

        pos = 0;

        if (need_dummy) {
            dummypage = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, ALLOC_TAG);
            if (!dummypage) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            dummy_mdl = IoAllocateMdl(dummypage, PAGE_SIZE, FALSE, FALSE, NULL);
            if (!dummy_mdl) {
                ERR("IoAllocateMdl failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            MmBuildMdlForNonPagedPool(dummy_mdl);

            dummy = *(PFN_NUMBER*)(dummy_mdl + 1);
        }

        MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

        for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
            if (ctxs[i].mdl)
                ctxs[i].pfnp = ctxs[i].pfns = MmGetMdlPfnArray(ctxs[i].mdl);
        }

        auto src_pfns = MmGetMdlPfnArray((tmpmdl ? tmpmdl : Irp->MdlAddress));

        while (pos < length) {
            if (pos == 0) {
                for (uint32_t i = startoffstripe; i < pdo->array_info.raid_disks; i++) {
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

                    RtlCopyMemory(ctxs[i].pfnp, src_pfns, sizeof(PFN_NUMBER) * pages);
                    src_pfns = &src_pfns[pages];
                    ctxs[i].pfnp = &ctxs[i].pfnp[pages];

                    pos += len;
                }

                // FIXME
            } else if (length - pos >= stripe_length * pdo->array_info.raid_disks) {
                uint32_t pages = stripe_length / PAGE_SIZE;

                for (uint32_t i = 0; i < pdo->array_info.raid_disks; i++) {
                    if (ctxs[i].pfnp != ctxs[i].pfns) {
                        for (uint32_t k = 0; k < stripe_length / PAGE_SIZE; k++) {
                            RtlCopyMemory(ctxs[i].pfnp, &dummy, sizeof(PFN_NUMBER));
                            ctxs[i].pfnp = &ctxs[i].pfnp[1];
                        }
                    }

                    RtlCopyMemory(ctxs[i].pfnp, src_pfns, sizeof(PFN_NUMBER) * pages);
                    src_pfns = &src_pfns[pages];
                    ctxs[i].pfnp = &ctxs[i].pfnp[pages];

                    pos += stripe_length;
                }
            } else {
                for (uint32_t i = 0; i < pdo->array_info.raid_disks; i++) {
                    uint32_t readlen, pages;

                    if (length - pos < stripe_length) {
                        readlen = length - pos;
                        pages = readlen / PAGE_SIZE;

                        if ((length - pos) % PAGE_SIZE != 0)
                            pages++;
                    } else {
                        readlen = stripe_length;
                        pages = stripe_length / PAGE_SIZE;
                    }

                    for (uint32_t k = 0; k < stripe_length / PAGE_SIZE; k++) {
                        if (ctxs[i].pfnp != ctxs[i].pfns) {
                            RtlCopyMemory(ctxs[i].pfnp, &dummy, sizeof(PFN_NUMBER));
                            ctxs[i].pfnp = &ctxs[i].pfnp[1];
                        }
                    }

                    RtlCopyMemory(ctxs[i].pfnp, src_pfns, sizeof(PFN_NUMBER) * pages);
                    src_pfns = &src_pfns[pages];
                    ctxs[i].pfnp = &ctxs[i].pfnp[pages];

                    pos += readlen;

                    if (pos == length)
                        break;
                }
            }
        }
    }

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].Irp) {
            ctxs[i].Status = IoCallDriver(ctxs[i].sc->device, ctxs[i].Irp);
            if (!NT_SUCCESS(ctxs[i].Status))
                ERR("IoCallDriver returned %08x\n", ctxs[i].Status);
        }
    }

    Status = STATUS_SUCCESS;

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].Status == STATUS_PENDING) {
            KeWaitForSingleObject(&ctxs[i].Event, Executive, KernelMode, false, nullptr);
            ctxs[i].Status = ctxs[i].iosb.Status;
        }

        if (!NT_SUCCESS(ctxs[i].Status))
            Status = ctxs[i].Status;
    }

    if (tmpbuf) {
        auto dest = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

        RtlCopyMemory(dest, tmpbuf + skip_first, length - skip_first);
    }

end:
    if (!mdl_locked)
        MmUnlockPages(Irp->MdlAddress);

    if (dummy_mdl)
        IoFreeMdl(dummy_mdl);

    if (dummypage)
        ExFreePool(dummypage);

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].mdl)
            IoFreeMdl(ctxs[i].mdl);

        if (ctxs[i].va)
            ExFreePool(ctxs[i].va);

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

NTSTATUS read_raid10(set_pdo* pdo, PIRP Irp, bool* no_complete) {
    NTSTATUS Status;
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);
    bool mdl_locked = true;
    uint8_t near, far;
    bool is_offset;
    uint64_t offset, start_chunk, end_chunk;
    uint32_t length;
    uint64_t startoff, endoff;
    uint32_t startoffstripe, endoffstripe;
    uint8_t* tmpbuf;
    PMDL tmpmdl;
    uint32_t stripe_length, skip_first;
    uint32_t near_shift, far_shift;
    io_context* ctxs;

    ExAcquireResourceSharedLite(&pdo->lock, true);

    if (pdo->array_info.chunksize == 0 || (pdo->array_info.chunksize * 512) % PAGE_SIZE != 0) {
        Status = STATUS_INTERNAL_ERROR;
        goto end2;
    }

    near = pdo->array_info.layout & 0xff;
    far = (pdo->array_info.layout >> 8) & 0xff;
    is_offset = pdo->array_info.layout & 0x10000;

    pdo->read_device++;

    if (is_offset) {
        Status = read_raid10_offset(pdo, Irp, no_complete);
        goto end2;
    }

    if (pdo->array_info.raid_disks % near != 0) {
        Status = read_raid10_odd(pdo, Irp, no_complete);
        goto end2;
    }

    offset = IrpSp->Parameters.Read.ByteOffset.QuadPart;
    length = IrpSp->Parameters.Read.Length;
    start_chunk = offset / (pdo->array_info.chunksize * 512);
    end_chunk = (offset + length - 1) / (pdo->array_info.chunksize * 512);

    if (start_chunk == end_chunk) { // small reads, on one device
        uint32_t near_shift = pdo->read_device % near;
        uint32_t far_shift = (pdo->read_device % (far * near)) / near;
        uint32_t disk_num = ((near * (start_chunk % (pdo->array_info.raid_disks / near))) + near_shift + (far_shift * near)) % pdo->array_info.raid_disks;

        auto c = pdo->child_list[disk_num];

        IoCopyCurrentIrpStackLocationToNext(Irp);

        auto IrpSp2 = IoGetNextIrpStackLocation(Irp);

        uint64_t start = (start_chunk / (pdo->array_info.raid_disks / near)) * (pdo->array_info.chunksize * 512);

        start += offset % (pdo->array_info.chunksize * 512);
        start += c->disk_info.data_offset * 512;
        start += far_shift * (c->disk_info.data_size / far) * 512;

        IrpSp2->FileObject = c->fileobj;
        IrpSp2->Parameters.Read.ByteOffset.QuadPart = start;

        *no_complete = true;

        Status = IoCallDriver(c->device, Irp);
        goto end2;
    }

    tmpbuf = nullptr;
    tmpmdl = nullptr;

    stripe_length = pdo->array_info.chunksize * 512;

    skip_first = offset % PAGE_SIZE;

    offset -= skip_first;
    length += skip_first;

    get_raid0_offset(offset, stripe_length, pdo->array_info.raid_disks / near, &startoff, &startoffstripe);
    get_raid0_offset(offset + length - 1, stripe_length, pdo->array_info.raid_disks / near, &endoff, &endoffstripe);

    ctxs = (io_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context) * pdo->array_info.raid_disks / near, ALLOC_TAG);
    if (!ctxs) {
        ERR("out of memory\n");
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto end2;
    }

    RtlZeroMemory(ctxs, sizeof(io_context) * pdo->array_info.raid_disks / near);

    for (unsigned int i = 0; i < pdo->array_info.raid_disks / near; i++) {
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

    near_shift = pdo->read_device % near;
    far_shift = (pdo->read_device % (far * near)) / near;

    for (unsigned int i = 0; i < pdo->array_info.raid_disks / near; i++) {
        if (ctxs[i].stripe_end != ctxs[i].stripe_start) {
            uint32_t disk_num = ((near * i) + near_shift + (far_shift * near)) % pdo->array_info.raid_disks;

            ctxs[i].Irp = IoAllocateIrp(pdo->child_list[disk_num]->device->StackSize, false);

            if (!ctxs[i].Irp) {
                ERR("IoAllocateIrp failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            auto IrpSp2 = IoGetNextIrpStackLocation(ctxs[i].Irp);
            IrpSp2->MajorFunction = IRP_MJ_READ;

            ctxs[i].mdl = IoAllocateMdl(nullptr, (ULONG)(ctxs[i].stripe_end - ctxs[i].stripe_start), false, false, nullptr);
            if (!ctxs[i].mdl) {
                ERR("IoAllocateMdl failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            ctxs[i].mdl->MdlFlags |= MDL_PARTIAL;

            ctxs[i].Irp->MdlAddress = ctxs[i].mdl;
            ctxs[i].sc = pdo->child_list[disk_num];

            IrpSp2->FileObject = pdo->child_list[disk_num]->fileobj;
            IrpSp2->Parameters.Read.Length = (ULONG)(ctxs[i].stripe_end - ctxs[i].stripe_start);
            IrpSp2->Parameters.Read.ByteOffset.QuadPart = ctxs[i].stripe_start;

            IrpSp2->Parameters.Read.ByteOffset.QuadPart += pdo->child_list[disk_num]->disk_info.data_offset * 512;
            IrpSp2->Parameters.Read.ByteOffset.QuadPart += far_shift * (pdo->child_list[disk_num]->disk_info.data_size / far) * 512;

            ctxs[i].Irp->UserIosb = &ctxs[i].iosb;

            KeInitializeEvent(&ctxs[i].Event, NotificationEvent, false);
            ctxs[i].Irp->UserEvent = &ctxs[i].Event;

            IoSetCompletionRoutine(ctxs[i].Irp, io_completion, &ctxs[i], true, true, true);
        } else
            ctxs[i].Status = STATUS_SUCCESS;
    }

    mdl_locked = Irp->MdlAddress->MdlFlags & (MDL_PAGES_LOCKED | MDL_PARTIAL);

    if (!mdl_locked) {
        Status = STATUS_SUCCESS;

        seh_try {
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoWriteAccess);
        } seh_except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (!NT_SUCCESS(Status)) {
            ERR("MmProbeAndLockPages threw exception %08x\n", Status);
            mdl_locked = true;
            goto end;
        }
    }

    if (Irp->MdlAddress->ByteOffset != 0 || skip_first != 0) {
        tmpbuf = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, length, ALLOC_TAG);
        if (!tmpbuf) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        tmpmdl = IoAllocateMdl(tmpbuf, length, false, false, nullptr);
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

        for (unsigned int i = 0; i < pdo->array_info.raid_disks / near; i++) {
            if (ctxs[i].mdl)
                ctxs[i].pfnp = ctxs[i].pfns = MmGetMdlPfnArray(ctxs[i].mdl);
        }

        auto src_pfns = MmGetMdlPfnArray((tmpmdl ? tmpmdl : Irp->MdlAddress));

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

            stripe = (stripe + 1) % (pdo->array_info.raid_disks / near);
        }
    }

    for (unsigned int i = 0; i < pdo->array_info.raid_disks / near; i++) {
        if (ctxs[i].Irp) {
            ctxs[i].Status = IoCallDriver(ctxs[i].sc->device, ctxs[i].Irp);
            if (!NT_SUCCESS(ctxs[i].Status))
                ERR("IoCallDriver returned %08x\n", ctxs[i].Status);
        }
    }

    Status = STATUS_SUCCESS;

    for (unsigned int i = 0; i < pdo->array_info.raid_disks / near; i++) {
        if (ctxs[i].Status == STATUS_PENDING) {
            KeWaitForSingleObject(&ctxs[i].Event, Executive, KernelMode, false, nullptr);
            ctxs[i].Status = ctxs[i].iosb.Status;
        }

        if (!NT_SUCCESS(ctxs[i].Status))
            Status = ctxs[i].Status;
    }

    if (tmpbuf) {
        auto dest = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

        RtlCopyMemory(dest, tmpbuf + skip_first, length - skip_first);
    }

end:
    if (!mdl_locked)
        MmUnlockPages(Irp->MdlAddress);

    for (unsigned int i = 0; i < pdo->array_info.raid_disks / near; i++) {
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

end2:
    ExReleaseResourceLite(&pdo->lock);

    return Status;
}

static NTSTATUS write_raid10_odd(set_pdo* pdo, PIRP Irp) {
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);
    bool mdl_locked = true;
    uint8_t near = pdo->array_info.layout & 0xff;
    uint32_t stripe_length = pdo->array_info.chunksize * 512;
    uint64_t offset = IrpSp->Parameters.Write.ByteOffset.QuadPart;
    uint32_t length = IrpSp->Parameters.Write.Length;
    uint64_t start_chunk = offset / stripe_length;
    uint8_t* tmpbuf = nullptr;
    PMDL tmpmdl = nullptr;
    NTSTATUS Status;
    LIST_ENTRY first_bits;

    uint32_t skip_first = offset % PAGE_SIZE ? (PAGE_SIZE - (offset % PAGE_SIZE)) : 0;

    auto ctxs = (io_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context) * pdo->array_info.raid_disks, ALLOC_TAG);
    if (!ctxs) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ctxs, sizeof(io_context) * pdo->array_info.raid_disks);

    InitializeListHead(&first_bits);

    mdl_locked = Irp->MdlAddress->MdlFlags & (MDL_PAGES_LOCKED | MDL_PARTIAL);

    if (!mdl_locked) {
        Status = STATUS_SUCCESS;

        seh_try {
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoReadAccess);
        } seh_except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (!NT_SUCCESS(Status)) {
            ERR("MmProbeAndLockPages threw exception %08x\n", Status);
            mdl_locked = true;
            goto end;
        }
    }

    if (skip_first != 0) {
        auto addr = MmGetMdlVirtualAddress(Irp->MdlAddress);

        uint64_t chunk = start_chunk * near;

        for (uint32_t i = 0; i < near; i++) {
            uint32_t disk_num = (chunk + i) % pdo->array_info.raid_disks;

            auto last = (io_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context), ALLOC_TAG);
            if (!last) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            new (last) io_context(pdo->child_list[disk_num], 0, 0);

            InsertTailList(&first_bits, &last->list_entry);

            if (!NT_SUCCESS(last->Status)) {
                ERR("io_context constructor returned %08x\n", last->Status);
                Status = last->Status;
                goto end;
            }

            auto IrpSp2 = IoGetNextIrpStackLocation(last->Irp);
            IrpSp2->MajorFunction = IRP_MJ_WRITE;

            last->mdl = IoAllocateMdl(addr, skip_first, false, false, nullptr);
            if (!last->mdl) {
                ERR("IoAllocateMdl failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            IoBuildPartialMdl(Irp->MdlAddress, last->mdl, addr, skip_first);

            last->Irp->MdlAddress = last->mdl;

            uint64_t start = ((chunk + i) / pdo->array_info.raid_disks) * stripe_length;

            start += offset % stripe_length;
            start += last->sc->disk_info.data_offset * 512;

            IrpSp2->FileObject = last->sc->fileobj;
            IrpSp2->Parameters.Write.Length = skip_first;
            IrpSp2->Parameters.Write.ByteOffset.QuadPart = start;
        }

        offset += skip_first;
        length -= skip_first;
        start_chunk = offset / stripe_length;
    }

    if (length > 0) {
        {
            uint64_t chunk = start_chunk * near;
            uint32_t pos = 0;

            while (pos < length) {
                uint32_t len;

                if (pos == 0)
                    len = min(length, stripe_length - offset % stripe_length);
                else
                    len = min(length - pos, stripe_length);

                for (uint32_t i = 0; i < near; i++) {
                    uint32_t disk_num = (chunk + i) % pdo->array_info.raid_disks;

                    if (pos == 0) {
                        ctxs[disk_num].stripe_start = ((chunk + i) / pdo->array_info.raid_disks) * stripe_length;
                        ctxs[disk_num].stripe_start += offset % stripe_length;

                        ctxs[disk_num].stripe_end = ctxs[disk_num].stripe_start + len;
                    } else {
                        if (ctxs[disk_num].stripe_start == 0)
                            ctxs[disk_num].stripe_start = ((chunk + i) / pdo->array_info.raid_disks) * stripe_length;

                        ctxs[disk_num].stripe_end = (((chunk + i) / pdo->array_info.raid_disks) * stripe_length) + len;
                    }
                }

                pos += len;
                chunk += near;
            }
        }

        for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
            if (ctxs[i].stripe_end != ctxs[i].stripe_start) {
                ctxs[i].Irp = IoAllocateIrp(pdo->child_list[i]->device->StackSize, false);

                if (!ctxs[i].Irp) {
                    ERR("IoAllocateIrp failed\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }

                auto IrpSp2 = IoGetNextIrpStackLocation(ctxs[i].Irp);
                IrpSp2->MajorFunction = IRP_MJ_WRITE;

                ctxs[i].mdl = IoAllocateMdl(nullptr, (ULONG)(ctxs[i].stripe_end - ctxs[i].stripe_start), false, false, nullptr);
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

                IoSetCompletionRoutine(ctxs[i].Irp, io_completion, &ctxs[i], true, true, true);
            } else
                ctxs[i].Status = STATUS_SUCCESS;
        }

        if (Irp->MdlAddress->ByteOffset != 0 || skip_first != 0) {
            tmpbuf = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, length, ALLOC_TAG);
            if (!tmpbuf) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            tmpmdl = IoAllocateMdl(tmpbuf, length, false, false, nullptr);
            if (!tmpmdl) {
                ERR("IoAllocateMdl failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            MmBuildMdlForNonPagedPool(tmpmdl);

            auto data = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

            RtlCopyMemory(tmpbuf, (uint8_t*)data + skip_first, length);
        }

        {
            uint64_t chunk = start_chunk * near;
            uint32_t pos = 0;
            MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

            for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
                if (ctxs[i].mdl)
                    ctxs[i].pfns = ctxs[i].pfnp = MmGetMdlPfnArray(ctxs[i].mdl);
            }

            auto src_pfns = MmGetMdlPfnArray((tmpmdl ? tmpmdl : Irp->MdlAddress));

            while (pos < length) {
                uint32_t len, pages;

                if (pos == 0)
                    len = min(length, stripe_length - (offset % stripe_length));
                else
                    len = min(length - pos, stripe_length);

                if (len % PAGE_SIZE != 0) {
                    pages = len / PAGE_SIZE;
                    pages++;
                } else
                    pages = len / PAGE_SIZE;

                for (uint32_t i = 0; i < near; i++) {
                    uint32_t disk_num = (chunk + i) % pdo->array_info.raid_disks;

                    RtlCopyMemory(ctxs[disk_num].pfnp, src_pfns, sizeof(PFN_NUMBER) * pages);

                    ctxs[disk_num].pfnp = &ctxs[disk_num].pfnp[pages];
                }

                src_pfns = &src_pfns[pages];
                pos += len;
                chunk += near;
            }
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
        LIST_ENTRY* le = first_bits.Flink;

        while (le != &first_bits) {
            auto fb = CONTAINING_RECORD(le, io_context, list_entry);

            fb->Status = IoCallDriver(fb->sc->device, fb->Irp);
            if (!NT_SUCCESS(fb->Status))
                ERR("IoCallDriver returned %08x\n", fb->Status);

            le = le->Flink;
        }
    }

    Status = STATUS_SUCCESS;

    for (unsigned int i = 0; i < pdo->array_info.raid_disks; i++) {
        if (ctxs[i].Status == STATUS_PENDING) {
            KeWaitForSingleObject(&ctxs[i].Event, Executive, KernelMode, false, nullptr);
            ctxs[i].Status = ctxs[i].iosb.Status;
        }

        if (!NT_SUCCESS(ctxs[i].Status))
            Status = ctxs[i].Status;
    }

    if (skip_first != 0) {
        while (!IsListEmpty(&first_bits)) {
            auto fb = CONTAINING_RECORD(RemoveHeadList(&first_bits), io_context, list_entry);

            if (fb->Status == STATUS_PENDING) {
                KeWaitForSingleObject(&fb->Event, Executive, KernelMode, false, nullptr);
                fb->Status = fb->iosb.Status;
            }

            if (!NT_SUCCESS(fb->Status))
                Status = fb->Status;

            fb->~io_context();
            ExFreePool(fb);
        }
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

    while (!IsListEmpty(&first_bits)) {
        io_context* ctx = CONTAINING_RECORD(RemoveHeadList(&first_bits), io_context, list_entry);

        ctx->~io_context();
        ExFreePool(ctx);
    }

    return Status;
}

static NTSTATUS write_raid10_offset_partial(set_pdo* pdo, LIST_ENTRY* ctxs, uint64_t offset, uint32_t length,
                                            PFN_NUMBER* src_pfns, uint32_t mdl_offset) {
    uint8_t far = (pdo->array_info.layout >> 8) & 0xff;
    uint64_t startoff, endoff;
    uint32_t startoffstripe, endoffstripe;

    uint32_t stripe_length = pdo->array_info.chunksize * 512;

    get_raid0_offset(offset, stripe_length, pdo->array_info.raid_disks, &startoff, &startoffstripe);
    get_raid0_offset(offset + length - 1, stripe_length, pdo->array_info.raid_disks, &endoff, &endoffstripe);

    uint32_t pos = 0;
    PFN_NUMBER* pfns = src_pfns;

    for (uint32_t i = startoffstripe; i <= endoffstripe; i++) {
        uint64_t stripe_start = ((startoff - (startoff % stripe_length)) * far) + (i == startoffstripe ? (startoff % stripe_length) : 0);
        uint32_t len = min(length - pos, i == startoffstripe ? (stripe_length - (startoff % stripe_length)) : stripe_length);

        auto c = pdo->child_list[i];

        auto ctxa = (io_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context), ALLOC_TAG);
        if (!ctxa) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        new (ctxa) io_context(c, stripe_start + (c->disk_info.data_offset * 512), stripe_start + (c->disk_info.data_offset * 512) + len);

        InsertTailList(ctxs, &ctxa->list_entry);

        ctxa->mdl = IoAllocateMdl(nullptr, len + mdl_offset, false, false, nullptr);
        if (!ctxa->mdl) {
            ERR("IoAllocateMdl failed\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ctxa->mdl->MdlFlags |= MDL_PARTIAL;

        ctxa->mdl->ByteOffset = mdl_offset;

        ctxa->Irp->MdlAddress = ctxa->mdl;

        uint32_t pages = (len + mdl_offset) / PAGE_SIZE;

        if ((len + mdl_offset) % PAGE_SIZE != 0)
            pages++;

        auto ctx_pfns = MmGetMdlPfnArray(ctxa->mdl);

        RtlCopyMemory(ctx_pfns, pfns, pages * sizeof(PFN_NUMBER));
        pfns = &pfns[len / PAGE_SIZE];

        for (uint32_t k = 1; k < far; k++) {
            auto c = pdo->child_list[(i + 1) % pdo->array_info.raid_disks];

            auto ctxb = (io_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context), ALLOC_TAG);
            if (!ctxb) {
                ERR("out of memory\n");
                return STATUS_INSUFFICIENT_RESOURCES;
            }

            new (ctxb) io_context(c, stripe_start + (k * stripe_length) + (c->disk_info.data_offset * 512),
                                  stripe_start + len + (k * stripe_length) + (c->disk_info.data_offset * 512));

            InsertTailList(ctxs, &ctxb->list_entry);

            ctxb->Irp->MdlAddress = ctxa->mdl;
        }

        pos += len;
    }

    return STATUS_SUCCESS;
}

static NTSTATUS write_raid10_offset(set_pdo* pdo, PIRP Irp) {
    NTSTATUS Status;
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);
    bool mdl_locked;
    uint64_t offset = IrpSp->Parameters.Write.ByteOffset.QuadPart;
    uint32_t length = IrpSp->Parameters.Write.Length;
    uint32_t stripe_length = pdo->array_info.chunksize * 512;
    uint32_t full_stripe = pdo->array_info.raid_disks * stripe_length;
    LIST_ENTRY ctxs;

    mdl_locked = Irp->MdlAddress->MdlFlags & (MDL_PAGES_LOCKED | MDL_PARTIAL);

    if (!mdl_locked) {
        Status = STATUS_SUCCESS;

        seh_try {
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoWriteAccess);
        } seh_except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (!NT_SUCCESS(Status)) {
            ERR("MmProbeAndLockPages threw exception %08x\n", Status);
            return Status;
        }
    }

    InitializeListHead(&ctxs);

    auto src_pfns = MmGetMdlPfnArray(Irp->MdlAddress);
    uint32_t mdl_offset = Irp->MdlAddress->ByteOffset;

    if (offset % full_stripe != 0) {
        uint32_t partial_len = min(length, full_stripe - (offset % full_stripe));

        Status = write_raid10_offset_partial(pdo, &ctxs, offset, partial_len, src_pfns, mdl_offset);
        if (!NT_SUCCESS(Status)) {
            ERR("write_raid10_offset_partial returned %08x\n", Status);
            goto end;
        }

        offset += partial_len;
        length -= partial_len;

        if (length > 0) {
            uint32_t pages = partial_len / PAGE_SIZE;

            mdl_offset += partial_len % PAGE_SIZE;

            if (mdl_offset >= PAGE_SIZE) {
                mdl_offset -= PAGE_SIZE;
                pages++;
            }

            src_pfns = &src_pfns[pages];
        }
    }

    if (length % full_stripe != 0) {
        uint32_t partial_len = length % full_stripe;

        Status = write_raid10_offset_partial(pdo, &ctxs, offset + length - partial_len, partial_len,
                                             &src_pfns[(length - partial_len) / PAGE_SIZE], mdl_offset);
        if (!NT_SUCCESS(Status)) {
            ERR("write_raid10_offset_partial returned %08x\n", Status);
            goto end;
        }

        length -= partial_len;
    }

    if (length > 0) {
        uint8_t far = (pdo->array_info.layout >> 8) & 0xff;
        uint64_t stripe_start = (offset / full_stripe) * (stripe_length * far);
        uint32_t len = (length / full_stripe) * (stripe_length * far);

        auto mdlpfns = (PFN_NUMBER**)ExAllocatePoolWithTag(NonPagedPool, sizeof(PFN_NUMBER*) * pdo->array_info.raid_disks, ALLOC_TAG);
        if (!mdlpfns) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto end;
        }

        for (uint32_t i = 0; i < pdo->array_info.raid_disks; i++) {
            auto c = pdo->child_list[i];

            auto ctxa = (io_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context), ALLOC_TAG);
            if (!ctxa) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            new (ctxa) io_context(c, stripe_start + (c->disk_info.data_offset * 512), stripe_start + (c->disk_info.data_offset * 512) + len);

            InsertTailList(&ctxs, &ctxa->list_entry);

            ctxa->mdl = IoAllocateMdl(nullptr, len + mdl_offset, false, false, nullptr);
            if (!ctxa->mdl) {
                ERR("IoAllocateMdl failed\n");
                ExFreePool(mdlpfns);
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            ctxa->mdl->MdlFlags |= MDL_PARTIAL;

            ctxa->mdl->ByteOffset = mdl_offset;

            ctxa->Irp->MdlAddress = ctxa->mdl;

            mdlpfns[i] = MmGetMdlPfnArray(ctxa->mdl);
        }

        uint32_t pos = 0;
        auto pfns = src_pfns;
        uint32_t stripe_pages = stripe_length / PAGE_SIZE;

        while (pos < length) {
            for (uint32_t i = 0; i < pdo->array_info.raid_disks; i++) {
                for (uint32_t k = 0; k < far; k++) {
                    RtlCopyMemory(&mdlpfns[(i + k) % pdo->array_info.raid_disks][k * stripe_pages], pfns, sizeof(PFN_NUMBER) * stripe_pages);
                }

                pfns = &pfns[stripe_pages];
            }

            for (uint32_t i = 0; i < pdo->array_info.raid_disks; i++) {
                mdlpfns[i] = &mdlpfns[i][far * stripe_pages];
            }

            pos += full_stripe;
        }

        ExFreePool(mdlpfns);
    }

    {
        LIST_ENTRY* le = ctxs.Flink;
        while (le != &ctxs) {
            auto ctx = CONTAINING_RECORD(le, io_context, list_entry);

            auto IrpSp = IoGetNextIrpStackLocation(ctx->Irp);
            IrpSp->MajorFunction = IRP_MJ_WRITE;

            IrpSp->FileObject = ctx->sc->fileobj;
            IrpSp->Parameters.Write.ByteOffset.QuadPart = ctx->stripe_start;
            IrpSp->Parameters.Write.Length = (ULONG)(ctx->stripe_end - ctx->stripe_start);

            ctx->Status = IoCallDriver(ctx->sc->device, ctx->Irp);

            le = le->Flink;
        }
    }

    Status = STATUS_SUCCESS;

    while (!IsListEmpty(&ctxs)) {
        auto ctx = CONTAINING_RECORD(RemoveHeadList(&ctxs), io_context, list_entry);

        if (ctx->Status == STATUS_PENDING) {
            KeWaitForSingleObject(&ctx->Event, Executive, KernelMode, false, nullptr);
            ctx->Status = ctx->iosb.Status;
        }

        if (!NT_SUCCESS(ctx->Status)) {
            ERR("writing returned %08x\n", ctx->Status);
            Status = ctx->Status;
        }

        ctx->~io_context();
        ExFreePool(ctx);
    }

end:
    if (!mdl_locked)
        MmUnlockPages(Irp->MdlAddress);

    while (!IsListEmpty(&ctxs)) {
        auto ctx = CONTAINING_RECORD(RemoveHeadList(&ctxs), io_context, list_entry);

        ctx->~io_context();
        ExFreePool(ctx);
    }

    return Status;
}

NTSTATUS write_raid10(set_pdo* pdo, PIRP Irp) {
    NTSTATUS Status;
    auto IrpSp = IoGetCurrentIrpStackLocation(Irp);
    bool mdl_locked;
    uint8_t* tmpbuf = nullptr;
    PMDL tmpmdl = nullptr;
    LIST_ENTRY first_bits;

    if (pdo->array_info.chunksize == 0 || (pdo->array_info.chunksize * 512) % PAGE_SIZE != 0)
        return STATUS_INTERNAL_ERROR;

    uint32_t near = pdo->array_info.layout & 0xff;
    uint32_t far = (pdo->array_info.layout >> 8) & 0xff;
    bool is_offset = pdo->array_info.layout & 0x10000;

    if (is_offset)
        return write_raid10_offset(pdo, Irp);

    if (pdo->array_info.raid_disks % near != 0)
        return write_raid10_odd(pdo, Irp);

    uint64_t startoff, endoff;
    uint32_t startoffstripe, endoffstripe;

    uint32_t stripe_length = pdo->array_info.chunksize * 512;
    uint64_t offset = IrpSp->Parameters.Write.ByteOffset.QuadPart;
    uint32_t length = IrpSp->Parameters.Write.Length;
    uint32_t skip_first = offset % PAGE_SIZE ? (PAGE_SIZE - (offset % PAGE_SIZE)) : 0;

    auto ctxs = (io_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context) * pdo->array_info.raid_disks * far,
                                                   ALLOC_TAG);
    if (!ctxs) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(ctxs, sizeof(io_context) * pdo->array_info.raid_disks * far);

    InitializeListHead(&first_bits);

    mdl_locked = Irp->MdlAddress->MdlFlags & (MDL_PAGES_LOCKED | MDL_PARTIAL);

    if (!mdl_locked) {
        Status = STATUS_SUCCESS;

        seh_try {
            MmProbeAndLockPages(Irp->MdlAddress, KernelMode, IoReadAccess);
        } seh_except (EXCEPTION_EXECUTE_HANDLER) {
            Status = GetExceptionCode();
        }

        if (!NT_SUCCESS(Status)) {
            ERR("MmProbeAndLockPages threw exception %08x\n", Status);
            mdl_locked = true;
            goto end;
        }
    }

    if (skip_first != 0) {
        auto addr = MmGetMdlVirtualAddress(Irp->MdlAddress);

        get_raid0_offset(offset, stripe_length, pdo->array_info.raid_disks / near, &startoff, &startoffstripe);

        for (uint32_t j = 0; j < far; j++) {
            for (uint32_t i = 0; i < near; i++) {
                auto last = (io_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(io_context), ALLOC_TAG);
                if (!last) {
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }

                new (last) io_context(pdo->child_list[((startoffstripe * near) + i + (j * near)) % pdo->array_info.raid_disks], 0, 0);

                InsertTailList(&first_bits, &last->list_entry);

                if (!NT_SUCCESS(last->Status)) {
                    ERR("io_context constructor returned %08x\n", last->Status);
                    Status = last->Status;
                    goto end;
                }

                auto IrpSp2 = IoGetNextIrpStackLocation(last->Irp);
                IrpSp2->MajorFunction = IRP_MJ_WRITE;

                last->mdl = IoAllocateMdl(addr, skip_first, false, false, nullptr);
                if (!last->mdl) {
                    ERR("IoAllocateMdl failed\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }

                IoBuildPartialMdl(Irp->MdlAddress, last->mdl, addr, skip_first);

                last->Irp->MdlAddress = last->mdl;

                uint64_t start = startoff;

                start += last->sc->disk_info.data_offset * 512;
                start += j * (last->sc->disk_info.data_size / far) * 512;

                IrpSp2->FileObject = last->sc->fileobj;
                IrpSp2->Parameters.Write.Length = skip_first;
                IrpSp2->Parameters.Write.ByteOffset.QuadPart = start;
            }
        }

        offset += skip_first;
        length -= skip_first;
    }

    if (length > 0) {
        get_raid0_offset(offset, stripe_length, pdo->array_info.raid_disks / near, &startoff, &startoffstripe);
        get_raid0_offset(offset + length - 1, stripe_length, pdo->array_info.raid_disks / near, &endoff, &endoffstripe);

        for (unsigned int i = 0; i < pdo->array_info.raid_disks / near; i++) {
            if (startoffstripe > i)
                ctxs[near * far * i].stripe_start = startoff - (startoff % stripe_length) + stripe_length;
            else if (startoffstripe == i)
                ctxs[near * far * i].stripe_start = startoff;
            else
                ctxs[near * far * i].stripe_start = startoff - (startoff % stripe_length);

            if (endoffstripe > i)
                ctxs[near * far * i].stripe_end = endoff - (endoff % stripe_length) + stripe_length;
            else if (endoffstripe == i)
                ctxs[near * far * i].stripe_end = endoff + 1;
            else
                ctxs[near * far * i].stripe_end = endoff - (endoff % stripe_length);
        }

        for (unsigned int i = 0; i < pdo->array_info.raid_disks / near; i++) {
            auto& ctxa = ctxs[near * far * i];

            if (ctxa.stripe_end != ctxa.stripe_start) {
                ctxa.mdl = IoAllocateMdl(nullptr, (ULONG)(ctxa.stripe_end - ctxa.stripe_start), false, false, nullptr);
                if (!ctxa.mdl) {
                    ERR("IoAllocateMdl failed\n");
                    Status = STATUS_INSUFFICIENT_RESOURCES;
                    goto end;
                }

                ctxa.mdl->MdlFlags |= MDL_PARTIAL;

                for (unsigned int j = 0; j < near; j++) { // FIXME
                    for (unsigned int k = 0; k < far; k++) {
                        auto ctx = &ctxs[(near * far * i) + (j * far) + k];
                        uint32_t disk_num = ((near * i) + j + (k * near)) % pdo->array_info.raid_disks;

                        ctx->Irp = IoAllocateIrp(pdo->child_list[disk_num]->device->StackSize, false);

                        if (!ctx->Irp) {
                            ERR("IoAllocateIrp failed\n");
                            Status = STATUS_INSUFFICIENT_RESOURCES;
                            goto end;
                        }

                        ctx->sc = pdo->child_list[disk_num];

                        auto IrpSp2 = IoGetNextIrpStackLocation(ctx->Irp);
                        IrpSp2->MajorFunction = IRP_MJ_WRITE;

                        ctx->Irp->MdlAddress = ctxa.mdl;

                        IrpSp2->FileObject = pdo->child_list[disk_num]->fileobj;
                        IrpSp2->Parameters.Write.Length = (ULONG)(ctxa.stripe_end - ctxa.stripe_start);

                        IrpSp2->Parameters.Write.ByteOffset.QuadPart = ctxa.stripe_start;
                        IrpSp2->Parameters.Write.ByteOffset.QuadPart += (pdo->child_list[disk_num]->disk_info.data_offset * 512);
                        IrpSp2->Parameters.Write.ByteOffset.QuadPart += k * (pdo->child_list[disk_num]->disk_info.data_size / far) * 512;

                        ctx->Irp->UserIosb = &ctx->iosb;
                        KeInitializeEvent(&ctx->Event, NotificationEvent, false);
                        ctx->Irp->UserEvent = &ctx->Event;

                        IoSetCompletionRoutine(ctx->Irp, io_completion, ctx, true, true, true);
                    }
                }
            } else {
                for (unsigned int j = 0; j < near * far; j++) {
                    auto ctx = &ctxs[(near * far * i) + j];

                    ctx->Status = STATUS_SUCCESS;
                }
            }
        }

        if (Irp->MdlAddress->ByteOffset != 0 || skip_first != 0) {
            tmpbuf = (uint8_t*)ExAllocatePoolWithTag(NonPagedPool, length, ALLOC_TAG);
            if (!tmpbuf) {
                ERR("out of memory\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            tmpmdl = IoAllocateMdl(tmpbuf, length, false, false, nullptr);
            if (!tmpmdl) {
                ERR("IoAllocateMdl failed\n");
                Status = STATUS_INSUFFICIENT_RESOURCES;
                goto end;
            }

            MmBuildMdlForNonPagedPool(tmpmdl);

            auto data = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

            RtlCopyMemory(tmpbuf, (uint8_t*)data + skip_first, length);
        }

        {
            uint32_t pos = 0;
            uint32_t stripe = startoffstripe;
            MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);

            for (unsigned int i = 0; i < pdo->array_info.raid_disks / near; i++) {
                if (ctxs[i * near * far].mdl)
                    ctxs[i * near * far].pfnp = MmGetMdlPfnArray(ctxs[i * near * far].mdl);
            }

            auto src_pfns = MmGetMdlPfnArray((tmpmdl ? tmpmdl : Irp->MdlAddress));

            while (pos < length) {
                auto ctxa = &ctxs[stripe * near * far];

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

                RtlCopyMemory(ctxa->pfnp, src_pfns, sizeof(PFN_NUMBER) * pages);
                src_pfns = &src_pfns[pages];
                ctxa->pfnp = &ctxa->pfnp[pages];

                pos += len;

                stripe = (stripe + 1) % (pdo->array_info.raid_disks / near);
            }
        }
    }

    for (unsigned int i = 0; i < pdo->array_info.raid_disks * far; i++) {
        if (ctxs[i].Irp) {
            ctxs[i].Status = IoCallDriver(ctxs[i].sc->device, ctxs[i].Irp);
            if (!NT_SUCCESS(ctxs[i].Status))
                ERR("IoCallDriver returned %08x\n", ctxs[i].Status);
        }
    }

    if (skip_first != 0) {
        LIST_ENTRY* le = first_bits.Flink;

        while (le != &first_bits) {
            auto fb = CONTAINING_RECORD(le, io_context, list_entry);

            fb->Status = IoCallDriver(fb->sc->device, fb->Irp);
            if (!NT_SUCCESS(fb->Status))
                ERR("IoCallDriver returned %08x\n", fb->Status);

            le = le->Flink;
        }
    }

    Status = STATUS_SUCCESS;

    for (unsigned int i = 0; i < pdo->array_info.raid_disks * far; i++) {
        if (ctxs[i].Status == STATUS_PENDING) {
            KeWaitForSingleObject(&ctxs[i].Event, Executive, KernelMode, false, nullptr);
            ctxs[i].Status = ctxs[i].iosb.Status;
        }

        if (!NT_SUCCESS(ctxs[i].Status))
            Status = ctxs[i].Status;
    }

    if (skip_first != 0) {
        while (!IsListEmpty(&first_bits)) {
            auto fb = CONTAINING_RECORD(RemoveHeadList(&first_bits), io_context, list_entry);

            if (fb->Status == STATUS_PENDING) {
                KeWaitForSingleObject(&fb->Event, Executive, KernelMode, false, nullptr);
                fb->Status = fb->iosb.Status;
            }

            if (!NT_SUCCESS(fb->Status))
                Status = fb->Status;

            fb->~io_context();
            ExFreePool(fb);
        }
    }

end:
    if (!mdl_locked)
        MmUnlockPages(Irp->MdlAddress);

    for (unsigned int i = 0; i < pdo->array_info.raid_disks * far; i++) {
        if (ctxs[i].mdl)
            IoFreeMdl(ctxs[i].mdl);

        if (ctxs[i].Irp)
            IoFreeIrp(ctxs[i].Irp);
    }

    if (tmpmdl)
        IoFreeMdl(tmpmdl);

    if (tmpbuf)
        ExFreePool(tmpbuf);

    while (!IsListEmpty(&first_bits)) {
        io_context* ctx = CONTAINING_RECORD(RemoveHeadList(&first_bits), io_context, list_entry);

        ctx->~io_context();
        ExFreePool(ctx);
    }

    ExFreePool(ctxs);

    return Status;
}
