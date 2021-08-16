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
#include <mountmgr.h>
#include <stdint.h>
#include <stddef.h>

static const WCHAR drive_letter_prefix[] = L"\\DosDevices\\";

static char get_drive_letter2(MOUNTMGR_MOUNT_POINTS* points) {
    TRACE("%u points\n", points->NumberOfMountPoints);

    for (ULONG i = 0; i < points->NumberOfMountPoints; i++) {
        const MOUNTMGR_MOUNT_POINT& mmp = points->MountPoints[i];
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

char get_drive_letter(HANDLE h, const UNICODE_STRING& name) {
    NTSTATUS Status;
    USHORT mmmp_len = sizeof(MOUNTMGR_MOUNT_POINT) + name.Length;
    char ret;

    MOUNTMGR_MOUNT_POINT* mmmp = (MOUNTMGR_MOUNT_POINT*)ExAllocatePoolWithTag(NonPagedPool, mmmp_len, ALLOC_TAG);

    if (!mmmp) {
        ERR("out of memory\n");
        return 0;
    }

    RtlZeroMemory(mmmp, mmmp_len);

    mmmp->DeviceNameOffset = sizeof(MOUNTMGR_MOUNT_POINT);
    mmmp->DeviceNameLength = name.Length;

    RtlCopyMemory((uint8_t*)mmmp + mmmp->DeviceNameOffset, name.Buffer, name.Length);

    MOUNTMGR_MOUNT_POINTS points;
    IO_STATUS_BLOCK iosb;

    Status = NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_MOUNTMGR_QUERY_POINTS,
                                   mmmp, mmmp_len, &points, sizeof(points));

    if (Status == STATUS_BUFFER_OVERFLOW && points.Size > 0) {
        MOUNTMGR_MOUNT_POINTS* points2 = (MOUNTMGR_MOUNT_POINTS*)ExAllocatePoolWithTag(NonPagedPool, points.Size, ALLOC_TAG);

        if (!points2) {
            ERR("out of memory\n");
            ret = 0;
            goto end;
        }

        Status = NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_MOUNTMGR_QUERY_POINTS,
                                       mmmp, mmmp_len, points2, points.Size);

        if (!NT_SUCCESS(Status)) {
            ERR("IOCTL_MOUNTMGR_QUERY_POINTS returned %08x\n", Status);
            ExFreePool(points2);
            ret = 0;
            goto end;
        }

        ret = get_drive_letter2(points2);

        ExFreePool(points2);
    } else if (!NT_SUCCESS(Status)) {
        ERR("IOCTL_MOUNTMGR_QUERY_POINTS returned %08x\n", Status);
        ret = 0;
    } else
        ret = get_drive_letter2(&points);

end:
    ExFreePool(mmmp);

    return ret;
}

NTSTATUS remove_drive_letter(HANDLE h, char c) {
    NTSTATUS Status;
    USHORT mmmp_len = sizeof(MOUNTMGR_MOUNT_POINT) + sizeof(drive_letter_prefix) + sizeof(WCHAR);

    MOUNTMGR_MOUNT_POINT* mmmp = (MOUNTMGR_MOUNT_POINT*)ExAllocatePoolWithTag(NonPagedPool, mmmp_len, ALLOC_TAG);

    if (!mmmp) {
        ERR("out of memory\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(mmmp, mmmp_len);

    mmmp->SymbolicLinkNameOffset = sizeof(MOUNTMGR_MOUNT_POINT);
    mmmp->SymbolicLinkNameLength = sizeof(drive_letter_prefix) + sizeof(WCHAR);

    WCHAR* symlink = (WCHAR*)((uint8_t*)mmmp + mmmp->SymbolicLinkNameOffset);

    RtlCopyMemory(symlink, drive_letter_prefix, sizeof(drive_letter_prefix) - sizeof(WCHAR));
    symlink[(sizeof(drive_letter_prefix) / sizeof(WCHAR)) - 1] = c;
    symlink[sizeof(drive_letter_prefix) / sizeof(WCHAR)] = ':';

    MOUNTMGR_MOUNT_POINTS points;
    IO_STATUS_BLOCK iosb;

    Status = NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_MOUNTMGR_DELETE_POINTS,
                                   mmmp, mmmp_len, &points, sizeof(points));

    if (Status == STATUS_BUFFER_OVERFLOW && points.Size > 0) {
        MOUNTMGR_MOUNT_POINTS* points2 = (MOUNTMGR_MOUNT_POINTS*)ExAllocatePoolWithTag(NonPagedPool, points.Size, ALLOC_TAG);
        if (!points2) {
            ERR("out of memory\n");
            ExFreePool(mmmp);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Status = NtDeviceIoControlFile(h, NULL, NULL, NULL, &iosb, IOCTL_MOUNTMGR_DELETE_POINTS,
                                       mmmp, mmmp_len, points2, points.Size);

        ExFreePool(points2);
    }

    if (!NT_SUCCESS(Status))
        ERR("IOCTL_MOUNTMGR_DELETE_POINTS returned %08x\n", Status);

    ExFreePool(mmmp);

    return Status;
}
