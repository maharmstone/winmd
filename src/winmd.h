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
#include <stdint.h>
#include <stdbool.h>
#include <uchar.h>
#include <mountdev.h>

#define DEBUG_PARANOID

#define ALLOC_TAG 0x6472444d // 'MDrd'

static const char16_t device_prefix[] = u"\\Device\\WinMD{";

#ifdef _DEBUG
typedef struct {
    PFILE_OBJECT comfo;
    PDEVICE_OBJECT comdo;
    ERESOURCE log_lock;
    bool unloading;
    HANDLE serial_thread_handle;
} serial_logger;

extern serial_logger* logger;

// logger.cpp
void do_log(const char* func, const char* msg, ...);
void init_serial_logger();
void stop_serial_logger();
#endif

#ifdef _MSC_VER
#define funcname __FUNCTION__
#else
#define funcname __func__
#endif

#ifndef min
#define min(a, b) (((a)<(b)) ? (a) : (b))
#endif

#ifndef max
#define max(a, b) (((a)>(b)) ? (a) : (b))
#endif

#ifndef FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL
#define FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL 0x00020000
#endif

#ifndef _MSC_VER
#define _Dispatch_type_(a)
#endif

extern uint32_t debug_log_level;
extern bool have_sse2;

#ifdef _DEBUG
#define ERR(s, ...) do { if (logger && debug_log_level > 0) { do_log(funcname, s, ##__VA_ARGS__); } } while (0);
#define FIXME(s, ...) do { if (logger && debug_log_level > 0) { do_log(funcname, s, ##__VA_ARGS__); } } while (0);
#define WARN(s, ...) do { if (logger && debug_log_level > 1) { do_log(funcname, s, ##__VA_ARGS__); } } while (0);
#define TRACE(s, ...) do { if (logger && debug_log_level > 2) { do_log(funcname, s, ##__VA_ARGS__); } } while (0);
#else
#define ERR(s, ...) do { } while (0);
#define FIXME(s, ...) do { } while (0);
#define WARN(s, ...) do { } while (0);
#define TRACE(s, ...) do { } while (0);
#endif

#if defined(_MSC_VER) || defined(__clang__)
#define try __try
#define except __except
#define finally __finally
#define leave __leave
#else
#define try if (1)
#define except(x) if (0 && (x))
#define finally if (1)
#define leave
#endif

enum device_type {
    device_type_control,
    device_type_set,
    device_type_pdo
};

typedef struct {
    enum device_type type;
    PDEVICE_OBJECT buspdo;
    PDEVICE_OBJECT attached_device;
    UNICODE_STRING bus_name;
} control_device;

__inline static uint64_t sector_align64(uint64_t n, uint64_t a) {
    if (n & (a - 1))
        n = (n + a) & ~(a - 1);

    return n;
}

__inline static uint32_t sector_align32(uint32_t n, uint32_t a) {
    if (n & (a - 1))
        n = (n + a) & ~(a - 1);

    return n;
}

#define RAID_12_OFFSET 0x1000

#define RAID_MAGIC 0xa92b4efc

#define RAID_LEVEL_MULTI_PATH   0xfffffffc
#define RAID_LEVEL_LINEAR       0xffffffff
#define RAID_LEVEL_0            0
#define RAID_LEVEL_1            1
#define RAID_LEVEL_4            4
#define RAID_LEVEL_5            5
#define RAID_LEVEL_6            6
#define RAID_LEVEL_10           10

#define RAID_LAYOUT_LEFT_ASYMMETRIC     0
#define RAID_LAYOUT_RIGHT_ASYMMETRIC    1
#define RAID_LAYOUT_LEFT_SYMMETRIC      2
#define RAID_LAYOUT_RIGHT_SYMMETRIC     3

#pragma pack(push,1)

typedef struct {
    uint64_t data_offset;
    uint64_t data_size;
    uint64_t super_offset;
    uint64_t recovery_offset;
    uint32_t dev_number;
    uint32_t cnt_correct_read;
    uint8_t device_uuid[16];
    uint8_t devflags;
} mdraid_disk_info;

typedef struct {
    uint8_t set_uuid[16];
    char set_name[32];
    uint64_t ctime;
    uint32_t level;
    uint32_t layout;
    uint64_t size;
    uint32_t chunksize;
    uint32_t raid_disks;
    uint32_t bitmap_offset;
} mdraid_array_info;

typedef struct {
    uint64_t utime;
    uint64_t events;
    uint64_t resync_offset;
    uint32_t sb_csum;
    uint32_t max_dev;
} mdraid_array_state;

typedef struct {
    uint16_t dev_roles[256]; // FIXME - is this the right maximum size?
} mdraid_roles;

typedef struct {
    uint32_t magic;
    uint32_t major_version;
    uint32_t feature_map;
    uint32_t pad0;
    mdraid_array_info array_info;
    uint32_t new_level;
    uint64_t reshape_position;
    uint32_t delta_disks;
    uint32_t new_layout;
    uint32_t new_chunk;
    uint32_t pad1;
    mdraid_disk_info disk_info;
    uint8_t pad2[7];
    mdraid_array_state array_state;
    uint8_t pad3[32];
    mdraid_roles roles;
} mdraid_superblock;

#pragma pack(pop)

typedef struct {
    PDEVICE_OBJECT device;
    PFILE_OBJECT fileobj;
    mdraid_disk_info disk_info;
    UNICODE_STRING devpath;
    LIST_ENTRY list_entry;
} set_child;

typedef struct {
    LIST_ENTRY list_entry;
    uint64_t offset;
    RTL_BITMAP bmp;
#ifdef _MSC_VER
    __declspec(align(16)) uint8_t data[1];
#else
    _Alignas(16) uint8_t data[1];
#endif
} partial_chunk;

typedef struct _set_pdo set_pdo;

typedef struct {
    enum device_type type;
    set_pdo* pdo;
    PDEVICE_OBJECT devobj;
    PDEVICE_OBJECT attached_device;
    LONG open_count;
    ERESOURCE lock;
} set_device;

typedef struct _set_pdo {
    enum device_type type;
    ERESOURCE lock;
    mdraid_array_info array_info;
    mdraid_array_state array_state;
    mdraid_roles roles;
    uint64_t array_size;
    set_child** child_list;
    LONG read_device;
    ULONG found_devices;
    bool loaded;
    PDEVICE_OBJECT pdo;
    set_device* dev;
    uint8_t stack_size;
    uint16_t dev_sector_size;
    LIST_ENTRY children;
    ERESOURCE partial_chunks_lock;
    LIST_ENTRY partial_chunks;
    LIST_ENTRY list_entry;
    HANDLE flush_thread_handle;
    KTIMER flush_thread_timer;
    KEVENT flush_thread_finished;
    bool readonly;
    UNICODE_STRING bus_name;
} set_pdo;

static __inline void get_raid0_offset(uint64_t off, uint64_t stripe_length, uint32_t num_stripes, uint64_t* stripeoff, uint32_t* stripe) {
    uint64_t initoff, startoff;

    startoff = off % (num_stripes * stripe_length);
    initoff = (off / (num_stripes * stripe_length)) * stripe_length;

    *stripe = (uint32_t)(startoff / stripe_length);
    *stripeoff = initoff + startoff - (*stripe * stripe_length);
}

// winmd.cpp
bool is_top_level(PIRP Irp);

// io.cpp
_Dispatch_type_(IRP_MJ_READ)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS drv_read(PDEVICE_OBJECT DeviceObject, PIRP Irp);

_Dispatch_type_(IRP_MJ_WRITE)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS drv_write(PDEVICE_OBJECT DeviceObject, PIRP Irp);

_Function_class_(KSTART_ROUTINE)
void __stdcall flush_thread(void* context);

void do_xor(uint8_t* buf1, uint8_t* buf2, uint32_t len);
NTSTATUS add_partial_chunk(set_pdo* pdo, uint64_t offset, uint32_t length, void* data);
void flush_chunks(set_pdo* pdo);
uint32_t get_parity_volume(set_pdo* pdo, uint64_t offset);
uint32_t get_physical_stripe(set_pdo* pdo, uint32_t stripe, uint32_t parity);

// pnp.cpp
_Dispatch_type_(IRP_MJ_PNP)
_Function_class_(DRIVER_DISPATCH)
NTSTATUS drv_pnp(PDEVICE_OBJECT DeviceObject, PIRP Irp);

_Function_class_(DRIVER_ADD_DEVICE)
NTSTATUS __stdcall AddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject);

// raid0.cpp
NTSTATUS read_raid0(set_pdo* pdo, PIRP Irp, bool* no_complete);
NTSTATUS write_raid0(set_pdo* pdo, PIRP Irp, bool* no_complete);

// raid1.cpp
NTSTATUS read_raid1(set_pdo* pdo, PIRP Irp, bool* no_complete);
NTSTATUS write_raid1(set_pdo* pdo, PIRP Irp);

// raid45.cpp
NTSTATUS read_raid45(set_pdo* pdo, PIRP Irp, bool* no_complete);
NTSTATUS write_raid45(set_pdo* pdo, PIRP Irp, bool* no_complete);
NTSTATUS flush_partial_chunk_raid45(set_pdo* pdo, partial_chunk* pc, RTL_BITMAP* valid_bmp);

// raid6.cpp
NTSTATUS read_raid6(set_pdo* pdo, PIRP Irp, bool* no_complete);
NTSTATUS write_raid6(set_pdo* pdo, PIRP Irp, bool* no_complete);
NTSTATUS flush_partial_chunk_raid6(set_pdo* pdo, partial_chunk* pc, RTL_BITMAP* valid_bmp);

// raid10.cpp
NTSTATUS read_raid10(set_pdo* pdo, PIRP Irp, bool* no_complete);
NTSTATUS write_raid10(set_pdo* pdo, PIRP Irp);

// linear.cpp
NTSTATUS read_linear(set_pdo* pdo, PIRP Irp, bool* no_complete);
NTSTATUS write_linear(set_pdo* pdo, PIRP Irp, bool* no_complete);

// mountmgr.cpp
char get_drive_letter(HANDLE h, const UNICODE_STRING* name);
NTSTATUS remove_drive_letter(HANDLE h, char c);
