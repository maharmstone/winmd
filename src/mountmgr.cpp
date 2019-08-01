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
#include "mountmgr.h"
#include <mountmgr.h>
#include <stdint.h>
#include <stddef.h>

static const WCHAR drive_letter_prefix[] = L"\\DosDevices\\";

using namespace std;

mountmgr::mountmgr() {
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES attr;
    IO_STATUS_BLOCK iosb;

    RtlInitUnicodeString(&us, MOUNTMGR_DEVICE_NAME);
    InitializeObjectAttributes(&attr, &us, 0, nullptr, nullptr);

    Status = NtOpenFile(&h, FILE_GENERIC_READ | FILE_GENERIC_WRITE, &attr, &iosb,
                        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_ALERT);
}

mountmgr::~mountmgr() {
    if (h)
        NtClose(h);
}

NTSTATUS mountmgr::volume_arrival_notification(const UNICODE_STRING& name) {
    USHORT mmtn_len = offsetof(MOUNTMGR_TARGET_NAME, DeviceName[0]) + name.Length;
    auto mmtn = (MOUNTMGR_TARGET_NAME*)ExAllocatePoolWithTag(PagedPool, mmtn_len, ALLOC_TAG);
    NTSTATUS Status;
    IO_STATUS_BLOCK iosb;

    if (!mmtn) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    mmtn->DeviceNameLength = name.Length;
    RtlCopyMemory(mmtn->DeviceName, name.Buffer, name.Length);

    Status = NtDeviceIoControlFile(h, nullptr, nullptr, nullptr, &iosb, IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION,
                                   mmtn, mmtn_len, nullptr, 0);

    ExFreePool(mmtn);

    if (!NT_SUCCESS(Status)) {
        ERR("NtDeviceIoControlFile returned %08x\n", Status);
        return Status;
    }

    return Status;
}

static char get_drive_letter2(MOUNTMGR_MOUNT_POINTS* points) {
    TRACE("%u points\n", points->NumberOfMountPoints);

    for (ULONG i = 0; i < points->NumberOfMountPoints; i++) {
        const auto& mmp = points->MountPoints[i];
        WCHAR* symlink = (WCHAR*)((uint8_t*)points + mmp.SymbolicLinkNameOffset);

        TRACE("point %u\n", i);
        TRACE("symbolic link %.*S\n", mmp.SymbolicLinkNameLength / sizeof(WCHAR), symlink);

        if (mmp.SymbolicLinkNameLength == sizeof(drive_letter_prefix) + sizeof(WCHAR) &&
            RtlCompareMemory(symlink, drive_letter_prefix, sizeof(drive_letter_prefix) - sizeof(WCHAR)) == sizeof(drive_letter_prefix) - sizeof(WCHAR) &&
            symlink[sizeof(drive_letter_prefix) / sizeof(WCHAR)] == ':')
            return (char)symlink[(sizeof(drive_letter_prefix) / sizeof(WCHAR)) - 1];
    }

    return 0;
}

char mountmgr::get_drive_letter(const UNICODE_STRING& name) {
    NTSTATUS Status;
    USHORT mmmp_len = sizeof(MOUNTMGR_MOUNT_POINT) + name.Length;

    np_buffer buf(mmmp_len);

    if (!buf.buf) {
        ERR("out of memory\n");
        return 0;
    }

    auto mmmp = (MOUNTMGR_MOUNT_POINT*)buf.buf;
    RtlZeroMemory(mmmp, mmmp_len);

    mmmp->DeviceNameOffset = sizeof(MOUNTMGR_MOUNT_POINT);
    mmmp->DeviceNameLength = name.Length;

    RtlCopyMemory((uint8_t*)mmmp + mmmp->DeviceNameOffset, name.Buffer, name.Length);

    MOUNTMGR_MOUNT_POINTS points;
    IO_STATUS_BLOCK iosb;

    Status = NtDeviceIoControlFile(h, nullptr, nullptr, nullptr, &iosb, IOCTL_MOUNTMGR_QUERY_POINTS,
                                   mmmp, mmmp_len, &points, sizeof(points));

    if (Status == STATUS_BUFFER_OVERFLOW && points.Size > 0) {
        np_buffer buf2(points.Size);

        if (!buf2.buf) {
            ERR("out of memory\n");
            return 0;
        }

        auto points2 = (MOUNTMGR_MOUNT_POINTS*)buf2.buf;

        Status = NtDeviceIoControlFile(h, nullptr, nullptr, nullptr, &iosb, IOCTL_MOUNTMGR_QUERY_POINTS,
                                       mmmp, mmmp_len, points2, points.Size);

        if (!NT_SUCCESS(Status)) {
            ERR("IOCTL_MOUNTMGR_QUERY_POINTS returned %08x\n", Status);
            return 0;
        }

        return get_drive_letter2(points2);
    } else if (!NT_SUCCESS(Status)) {
        ERR("IOCTL_MOUNTMGR_QUERY_POINTS returned %08x\n", Status);
        return 0;
    } else
        return get_drive_letter2(&points);
}

NTSTATUS mountmgr::remove_drive_letter(char c) {
    NTSTATUS Status;
    USHORT mmmp_len = sizeof(MOUNTMGR_MOUNT_POINT) + sizeof(drive_letter_prefix) + sizeof(WCHAR);

    np_buffer buf(mmmp_len);

    if (!buf.buf) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    auto mmmp = (MOUNTMGR_MOUNT_POINT*)buf.buf;
    RtlZeroMemory(mmmp, mmmp_len);

    mmmp->SymbolicLinkNameOffset = sizeof(MOUNTMGR_MOUNT_POINT);
    mmmp->SymbolicLinkNameLength = sizeof(drive_letter_prefix) + sizeof(WCHAR);

    auto symlink = (WCHAR*)((uint8_t*)mmmp + mmmp->SymbolicLinkNameOffset);

    RtlCopyMemory(symlink, drive_letter_prefix, sizeof(drive_letter_prefix) - sizeof(WCHAR));
    symlink[(sizeof(drive_letter_prefix) / sizeof(WCHAR)) - 1] = c;
    symlink[sizeof(drive_letter_prefix) / sizeof(WCHAR)] = ':';

    MOUNTMGR_MOUNT_POINTS points;
    IO_STATUS_BLOCK iosb;

    Status = NtDeviceIoControlFile(h, nullptr, nullptr, nullptr, &iosb, IOCTL_MOUNTMGR_DELETE_POINTS,
                                   mmmp, mmmp_len, &points, sizeof(points));

    if (Status == STATUS_BUFFER_OVERFLOW && points.Size > 0) {
        np_buffer buf2(points.Size);

        if (!buf2.buf) {
            ERR("out of memory\n");
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        auto points2 = (MOUNTMGR_MOUNT_POINTS*)buf2.buf;

        Status = NtDeviceIoControlFile(h, nullptr, nullptr, nullptr, &iosb, IOCTL_MOUNTMGR_DELETE_POINTS,
                                       mmmp, mmmp_len, points2, points.Size);
    }

    if (!NT_SUCCESS(Status))
        ERR("IOCTL_MOUNTMGR_DELETE_POINTS returned %08x\n", Status);

    return Status;
}

