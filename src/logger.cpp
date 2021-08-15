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
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef _DEBUG
typedef struct {
    KEVENT Event;
    IO_STATUS_BLOCK iosb;
} logger_context;

static const WCHAR log_device[] = L"\\Device\\Serial0";

void serial_logger::serial_thread() {
    LARGE_INTEGER due_time;
    KTIMER timer;

    KeInitializeTimer(&timer);

    due_time.QuadPart = (UINT64)-10000000;

    KeSetTimer(&timer, due_time, NULL);

    while (true) {
        KeWaitForSingleObject(&timer, Executive, KernelMode, false, nullptr);

        {
            UNICODE_STRING us;

            us.Buffer = (WCHAR*)log_device;
            us.Length = us.MaximumLength = sizeof(log_device) - sizeof(WCHAR);

            NTSTATUS Status = IoGetDeviceObjectPointer(&us, FILE_WRITE_DATA, &comfo, &comdo);
            if (!NT_SUCCESS(Status))
                ERR("IoGetDeviceObjectPointer returned %08x\n", Status);
        }

        if (comdo)
            break;

        KeSetTimer(&timer, due_time, NULL);
    }

    KeCancelTimer(&timer);

    serial_thread_handle = nullptr;

    PsTerminateSystemThread(STATUS_SUCCESS);
}

serial_logger::serial_logger() {
    NTSTATUS Status;
    UNICODE_STRING us;

    ExInitializeResourceLite(&log_lock);

    us.Buffer = (WCHAR*)log_device;
    us.Length = us.MaximumLength = sizeof(log_device) - sizeof(WCHAR);

    Status = IoGetDeviceObjectPointer(&us, FILE_WRITE_DATA, &comfo, &comdo);
    if (!NT_SUCCESS(Status)) {
        ERR("IoGetDeviceObjectPointer returned %08x\n", Status);

        Status = PsCreateSystemThread(&serial_thread_handle, 0, nullptr, nullptr, nullptr, [](void* context) {
            auto logger = (serial_logger*)context;

            logger->serial_thread();
        }, this);

        if (!NT_SUCCESS(Status)) {
            ERR("PsCreateSystemThread returned %08x\n", Status);
            return;
        }
    }
}

serial_logger::~serial_logger() {
    unloading = true;

    // sync
    ExAcquireResourceExclusiveLite(&log_lock, TRUE);
    ExReleaseResourceLite(&log_lock);

    if (comfo)
        ObDereferenceObject(comfo);

    if (serial_thread_handle)
        NtClose(serial_thread_handle);

    ExDeleteResourceLite(&log_lock);
}

static NTSTATUS __stdcall dbg_completion(PDEVICE_OBJECT, PIRP Irp, PVOID ctx) {
    auto context = (logger_context*)ctx;

    context->iosb = Irp->IoStatus;
    KeSetEvent(&context->Event, 0, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

void serial_logger::log(const char* func, const char* msg, ...) {
    NTSTATUS Status;
    PIRP Irp;
    PIO_STACK_LOCATION IrpSp;

    size_t buf_size = 1024;
    auto buf2 = (char*)ExAllocatePoolWithTag(NonPagedPool, buf_size, ALLOC_TAG);

    if (!buf2) {
        DbgPrint("Couldn't allocate buffer in debug_message\n");
        return;
    }

    _snprintf(buf2, buf_size, "%p:%s:", PsGetCurrentThread(), func);
    auto prefix_size = strlen(buf2);
    char* buf = &buf2[prefix_size];

    va_list ap;
    va_start(ap, msg);
    auto retlen = _vsnprintf(buf, buf_size - prefix_size, msg, ap);

    if (retlen < 0) {
        DbgPrint("vsnprintf encoding error\n");
        va_end(ap);
        ExFreePool(buf2);
        return;
    }

    if ((size_t)retlen > buf_size - prefix_size) { // data truncated
        buf_size = retlen + prefix_size + 1;

        auto buf3 = (char*)ExAllocatePoolWithTag(NonPagedPool, buf_size, ALLOC_TAG);
        if (!buf3) {
            DbgPrint("Out of memory.\n");
            va_end(ap);
            ExFreePool(buf2);
            return;
        }

        RtlCopyMemory(buf3, buf2, prefix_size);

        ExFreePool(buf2);
        buf2 = buf3;

        char* buf = &buf2[prefix_size];

        _vsnprintf(buf, buf_size - prefix_size, msg, ap);
    }

    if (unloading || !comfo) {
        DbgPrint(buf2);

        va_end(ap);

        ExFreePool(buf2);

        return;
    }

    ExAcquireResourceSharedLite(&log_lock, TRUE);

    auto length = (uint32_t)strlen(buf2);

    LARGE_INTEGER offset;
    offset.u.LowPart = 0;
    offset.u.HighPart = 0;

    logger_context* context = (logger_context*)ExAllocatePoolWithTag(NonPagedPool, sizeof(logger_context), ALLOC_TAG);
    if (!context) {
        DbgPrint("out of memory\n");
        goto exit2;
    }

    RtlZeroMemory(context, sizeof(logger_context));

    KeInitializeEvent(&context->Event, NotificationEvent, false);

    Irp = IoAllocateIrp(comdo->StackSize, false);

    if (!Irp) {
        DbgPrint("IoAllocateIrp failed\n");
        ExFreePool(context);
        goto exit2;
    }

    IrpSp = IoGetNextIrpStackLocation(Irp);
    IrpSp->MajorFunction = IRP_MJ_WRITE;

    if (comdo->Flags & DO_BUFFERED_IO) {
        Irp->AssociatedIrp.SystemBuffer = (void*)buf2;

        Irp->Flags = IRP_BUFFERED_IO;
    } else if (comdo->Flags & DO_DIRECT_IO) {
        Irp->MdlAddress = IoAllocateMdl((void*)buf2, length, false, false, nullptr);
        if (!Irp->MdlAddress) {
            DbgPrint("IoAllocateMdl failed\n");
            goto exit;
        }

        MmBuildMdlForNonPagedPool(Irp->MdlAddress);
    } else
        Irp->UserBuffer = (void*)buf2;

    IrpSp->Parameters.Write.Length = length;
    IrpSp->Parameters.Write.ByteOffset = offset;

    Irp->UserIosb = &context->iosb;

    Irp->UserEvent = &context->Event;

    IoSetCompletionRoutine(Irp, dbg_completion, context, TRUE, TRUE, TRUE);

    Status = IoCallDriver(comdo, Irp);

    if (Status == STATUS_PENDING) {
        LARGE_INTEGER timeout;

        timeout.QuadPart = -10000000ll; // 1 second

        KeWaitForSingleObject(&context->Event, Executive, KernelMode, false, &timeout);
        Status = context->iosb.Status;
    }

    if (comdo->Flags & DO_DIRECT_IO)
        IoFreeMdl(Irp->MdlAddress);

    if (!NT_SUCCESS(Status)) {
        DbgPrint("failed to write to COM1 - error %08x\n", Status);
        goto exit;
    }

exit:
    IoFreeIrp(Irp);
    ExFreePool(context);

exit2:
    ExReleaseResourceLite(&log_lock);

    va_end(ap);

    if (buf2)
        ExFreePool(buf2);
}
#endif
