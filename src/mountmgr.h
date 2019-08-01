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

#pragma once

#include <ntifs.h>

class mountmgr {
public:
    mountmgr();
    ~mountmgr();
    NTSTATUS volume_arrival_notification(const UNICODE_STRING& name);
    char get_drive_letter(const UNICODE_STRING& name);
    NTSTATUS remove_drive_letter(char c);

    NTSTATUS Status;

private:
    HANDLE h = nullptr;
};
