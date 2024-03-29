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
#include <ntstrsafe.h>

#ifdef _DEBUG
typedef struct {
    KEVENT Event;
    IO_STATUS_BLOCK iosb;
} logger_context;

static const WCHAR log_device[] = L"\\Device\\Serial0";

_Function_class_(KSTART_ROUTINE)
static void __stdcall serial_thread(void* context) {
    LARGE_INTEGER due_time;
    KTIMER timer;

    KeInitializeTimer(&timer);

    due_time.QuadPart = (UINT64)-10000000;

    KeSetTimer(&timer, due_time, NULL);

    while (true) {
        KeWaitForSingleObject(&timer, Executive, KernelMode, false, NULL);

        {
            UNICODE_STRING us;

            us.Buffer = (WCHAR*)log_device;
            us.Length = us.MaximumLength = sizeof(log_device) - sizeof(WCHAR);

            NTSTATUS Status = IoGetDeviceObjectPointer(&us, FILE_WRITE_DATA, &logger->comfo, &logger->comdo);
            if (!NT_SUCCESS(Status))
                ERR("IoGetDeviceObjectPointer returned %08x\n", Status);
        }

        if (logger->comdo)
            break;

        KeSetTimer(&timer, due_time, NULL);
    }

    KeCancelTimer(&timer);

    logger->serial_thread_handle = NULL;

    PsTerminateSystemThread(STATUS_SUCCESS);
}

void init_serial_logger() {
    NTSTATUS Status;
    UNICODE_STRING us;

    logger->unloading = false;
    logger->serial_thread_handle = NULL;

    ExInitializeResourceLite(&logger->log_lock);

    us.Buffer = (WCHAR*)log_device;
    us.Length = us.MaximumLength = sizeof(log_device) - sizeof(WCHAR);

    Status = IoGetDeviceObjectPointer(&us, FILE_WRITE_DATA, &logger->comfo, &logger->comdo);
    if (!NT_SUCCESS(Status)) {
        ERR("IoGetDeviceObjectPointer returned %08x\n", Status);

        Status = PsCreateSystemThread(&logger->serial_thread_handle, 0, NULL, NULL, NULL, serial_thread, logger);

        if (!NT_SUCCESS(Status)) {
            ERR("PsCreateSystemThread returned %08x\n", Status);
            return;
        }
    }
}

void stop_serial_logger() {
    logger->unloading = true;

    // sync
    ExAcquireResourceExclusiveLite(&logger->log_lock, TRUE);
    ExReleaseResourceLite(&logger->log_lock);

    if (logger->comfo)
        ObDereferenceObject(logger->comfo);

    if (logger->serial_thread_handle)
        NtClose(logger->serial_thread_handle);

    ExDeleteResourceLite(&logger->log_lock);
}

_Function_class_(IO_COMPLETION_ROUTINE)
static NTSTATUS __stdcall dbg_completion(PDEVICE_OBJECT devobj, PIRP Irp, PVOID ctx) {
    logger_context* context = ctx;

    context->iosb = Irp->IoStatus;
    KeSetEvent(&context->Event, 0, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

void do_log(const char* func, const char* msg, ...) {
    NTSTATUS Status;
    PIRP Irp;
    PIO_STACK_LOCATION IrpSp;

    static const size_t buf_size = 1024;
    char* buf2 = ExAllocatePoolWithTag(NonPagedPool, buf_size, ALLOC_TAG);

    if (!buf2) {
        DbgPrint("Couldn't allocate buffer in debug_message\n");
        return;
    }

    sprintf(buf2, "%p:%s:", PsGetCurrentThread(), func);
    size_t prefix_size = strlen(buf2);
    char* buf = &buf2[prefix_size];

    va_list ap;
    va_start(ap, msg);

    RtlStringCbVPrintfA(buf, buf_size - strlen(buf2), msg, ap);

    if (logger->unloading || !logger->comfo) {
        DbgPrint(buf2);

        va_end(ap);

        ExFreePool(buf2);

        return;
    }

    ExAcquireResourceSharedLite(&logger->log_lock, true);

    uint32_t length = (uint32_t)strlen(buf2);

    LARGE_INTEGER offset;
    offset.u.LowPart = 0;
    offset.u.HighPart = 0;

    logger_context* context = ExAllocatePoolWithTag(NonPagedPool, sizeof(logger_context), ALLOC_TAG);
    if (!context) {
        DbgPrint("out of memory\n");
        goto exit2;
    }

    RtlZeroMemory(context, sizeof(logger_context));

    KeInitializeEvent(&context->Event, NotificationEvent, false);

    Irp = IoAllocateIrp(logger->comdo->StackSize, false);

    if (!Irp) {
        DbgPrint("IoAllocateIrp failed\n");
        ExFreePool(context);
        goto exit2;
    }

    IrpSp = IoGetNextIrpStackLocation(Irp);
    IrpSp->MajorFunction = IRP_MJ_WRITE;

    if (logger->comdo->Flags & DO_BUFFERED_IO) {
        Irp->AssociatedIrp.SystemBuffer = (void*)buf2;

        Irp->Flags = IRP_BUFFERED_IO;
    } else if (logger->comdo->Flags & DO_DIRECT_IO) {
        Irp->MdlAddress = IoAllocateMdl((void*)buf2, length, false, false, NULL);
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

    Status = IoCallDriver(logger->comdo, Irp);

    if (Status == STATUS_PENDING) {
        LARGE_INTEGER timeout;

        timeout.QuadPart = -10000000ll; // 1 second

        KeWaitForSingleObject(&context->Event, Executive, KernelMode, false, &timeout);
        Status = context->iosb.Status;
    }

    if (logger->comdo->Flags & DO_DIRECT_IO)
        IoFreeMdl(Irp->MdlAddress);

    if (!NT_SUCCESS(Status)) {
        DbgPrint("failed to write to COM1 - error %08x\n", Status);
        goto exit;
    }

exit:
    IoFreeIrp(Irp);
    ExFreePool(context);

exit2:
    ExReleaseResourceLite(&logger->log_lock);

    va_end(ap);

    if (buf2)
        ExFreePool(buf2);
}
#endif
