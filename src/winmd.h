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
#include <mountdev.h>
#include <new>

// #define DEBUG_PARANOID

#define ALLOC_TAG 0x6472444d // 'MDrd'

static const char16_t device_prefix[] = u"\\Device\\WinMD{";

#ifdef _DEBUG
class serial_logger {
public:
    serial_logger();
    ~serial_logger();

    void log(const char* func, const char* msg, ...);

private:
    void serial_thread();

    PFILE_OBJECT comfo = nullptr;
    PDEVICE_OBJECT comdo = nullptr;
    ERESOURCE log_lock;
    bool unloading = false;
    HANDLE serial_thread_handle = nullptr;
};

extern serial_logger* logger;
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

extern uint32_t debug_log_level;
extern bool have_sse2;

#ifdef _DEBUG
#define ERR(s, ...) do { if (logger && debug_log_level > 0) { logger->log(funcname, s, ##__VA_ARGS__); } } while (0);
#define FIXME(s, ...) do { if (logger && debug_log_level > 0) { logger->log(funcname, s, ##__VA_ARGS__); } } while (0);
#define WARN(s, ...) do { if (logger && debug_log_level > 1) { logger->log(funcname, s, ##__VA_ARGS__); } } while (0);
#define TRACE(s, ...) do { if (logger && debug_log_level > 2) { logger->log(funcname, s, ##__VA_ARGS__); } } while (0);
#else
#define ERR(s, ...) do { } while (0);
#define FIXME(s, ...) do { } while (0);
#define WARN(s, ...) do { } while (0);
#define TRACE(s, ...) do { } while (0);
#endif

#ifdef _MSC_VER
#define seh_try __try
#define seh_except __except
#define seh_finally __finally
#else
#define seh_try if (1)
#define seh_except(x) if (0 && (x))
#define seh_finally if (1)
#endif

class device {
public:
    virtual NTSTATUS create(PIRP Irp);
    virtual NTSTATUS read(PIRP Irp, bool* no_complete);
    virtual NTSTATUS write(PIRP Irp, bool* no_complete);
    virtual NTSTATUS device_control(PIRP Irp);
    virtual NTSTATUS close(PIRP Irp);
    virtual NTSTATUS pnp(PIRP Irp, bool* no_complete);
    virtual NTSTATUS shutdown(PIRP Irp);
    virtual NTSTATUS power(PIRP Irp);
    virtual NTSTATUS system_control(PIRP Irp, bool* no_complete);
};

class control_device : device {
public:
    NTSTATUS create(PIRP Irp) override;
    NTSTATUS pnp(PIRP Irp, bool* no_complete) override;
    NTSTATUS power(PIRP Irp) override;
    NTSTATUS system_control(PIRP Irp, bool* no_complete) override;

    PDEVICE_OBJECT buspdo;
    PDEVICE_OBJECT attached_device;
    UNICODE_STRING bus_name;
};

__inline static uint64_t sector_align(uint64_t n, uint64_t a) {
    if (n & (a - 1))
        n = (n + a) & ~(a - 1);

    return n;
}

__inline static uint32_t sector_align(uint32_t n, uint32_t a) {
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

struct mdraid_disk_info {
    uint64_t data_offset;
    uint64_t data_size;
    uint64_t super_offset;
    uint64_t recovery_offset;
    uint32_t dev_number;
    uint32_t cnt_correct_read;
    uint8_t device_uuid[16];
    uint8_t devflags;
};

struct mdraid_array_info {
    uint8_t set_uuid[16];
    char set_name[32];
    uint64_t ctime;
    uint32_t level;
    uint32_t layout;
    uint64_t size;
    uint32_t chunksize;
    uint32_t raid_disks;
    uint32_t bitmap_offset;
};

struct mdraid_array_state {
    uint64_t utime;
    uint64_t events;
    uint64_t resync_offset;
    uint32_t sb_csum;
    uint32_t max_dev;
};

struct mdraid_roles {
    uint16_t dev_roles[256]; // FIXME - is this the right maximum size?
};

struct mdraid_superblock {
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
};

#pragma pack(pop)

class set_child {
public:
    set_child(PDEVICE_OBJECT device, PFILE_OBJECT fileobj, PUNICODE_STRING devpath, mdraid_disk_info* disk_info);
    ~set_child();

    PDEVICE_OBJECT device;
    PFILE_OBJECT fileobj;
    mdraid_disk_info disk_info;
    UNICODE_STRING devpath;
    LIST_ENTRY list_entry;
    NTSTATUS Status;
};

struct partial_chunk {
    LIST_ENTRY list_entry;
    uint64_t offset;
    RTL_BITMAP bmp;
    alignas(16) uint8_t data[1];
};

class io_context;
class set_pdo;

class set_device : device {
public:
    set_device(set_pdo* pdo, PDEVICE_OBJECT devobj) : pdo(pdo), devobj(devobj) {
        ExInitializeResourceLite(&lock);
    }

    ~set_device() {
        ExDeleteResourceLite(&lock);
    }

    NTSTATUS create(PIRP Irp) override;
    NTSTATUS close(PIRP Irp) override;
    NTSTATUS pnp(PIRP Irp, bool* no_complete) override;
    NTSTATUS device_control(PIRP Irp) override;
    NTSTATUS system_control(PIRP Irp, bool* no_complete) override;
    NTSTATUS read(PIRP Irp, bool* no_complete) override;
    NTSTATUS write(PIRP Irp, bool* no_complete) override;

    set_pdo* pdo;
    PDEVICE_OBJECT devobj;
    PDEVICE_OBJECT attached_device;
    LONG open_count = 0;
    ERESOURCE lock;
};

class set_pdo : device {
public:
    set_pdo();
    ~set_pdo();

    NTSTATUS create(PIRP Irp) override;
    NTSTATUS close(PIRP Irp) override;
    NTSTATUS pnp(PIRP Irp, bool* no_complete) override;
    NTSTATUS shutdown(PIRP Irp) override;
    void flush_thread();
    void child_removed(set_child* sc);
    NTSTATUS AddDevice();

    friend set_device;

    ERESOURCE lock;
    mdraid_array_info array_info;
    mdraid_array_state array_state;
    mdraid_roles roles;
    uint64_t array_size = 0;
    set_child** child_list;
    LONG read_device = 0;
    ULONG found_devices = 0;
    bool loaded = false;
    PDEVICE_OBJECT pdo;
    set_device* dev = nullptr;

    uint8_t stack_size = 0;
    uint16_t dev_sector_size = 0;
    LIST_ENTRY children;
    ERESOURCE partial_chunks_lock;
    LIST_ENTRY partial_chunks;
    LIST_ENTRY list_entry;
    HANDLE flush_thread_handle = nullptr;
    KTIMER flush_thread_timer;
    KEVENT flush_thread_finished;
    bool readonly = false;
    UNICODE_STRING bus_name;

private:
    NTSTATUS read_raid45(PIRP Irp, bool* no_complete);
    NTSTATUS read_raid6(PIRP Irp, bool* no_complete);
    NTSTATUS read_raid10(PIRP Irp, bool* no_complete);
    NTSTATUS read_raid10_odd(PIRP Irp, bool* no_complete);
    NTSTATUS read_raid10_offset(PIRP Irp, bool* no_complete);
    NTSTATUS read_linear(PIRP Irp, bool* no_complete);
    NTSTATUS write_raid45(PIRP Irp, bool* no_complete);
    NTSTATUS write_raid6(PIRP Irp, bool* no_complete);
    NTSTATUS write_raid10(PIRP Irp);
    NTSTATUS write_raid10_odd(PIRP Irp);
    NTSTATUS write_raid10_offset(PIRP Irp);
    NTSTATUS write_raid10_offset_partial(LIST_ENTRY* ctxs, uint64_t offset, uint32_t length, PFN_NUMBER* src_pfns, uint32_t mdl_offset);
    NTSTATUS write_linear(PIRP Irp, bool* no_complete);
    NTSTATUS add_partial_chunk(uint64_t offset, uint32_t length, void* data);
    NTSTATUS flush_partial_chunk(partial_chunk* pc);
    NTSTATUS flush_partial_chunk_raid45(partial_chunk* pc, RTL_BITMAP* valid_bmp);
    NTSTATUS flush_partial_chunk_raid6(partial_chunk* pc, RTL_BITMAP* valid_bmp);
    void flush_chunks();
    uint32_t get_parity_volume(uint64_t offset);
    uint32_t get_physical_stripe(uint32_t stripe, uint32_t parity);
    NTSTATUS io_linear2(PIRP Irp, uint64_t offset, uint32_t start_disk, bool write);
#ifdef DEBUG_PARANOID
    void paranoid_raid5_check(uint64_t parity_offset, uint32_t parity_length);
    void paranoid_raid6_check(uint64_t parity_offset, uint32_t parity_length);
#endif
};

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
NTSTATUS drv_read(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS drv_write(PDEVICE_OBJECT DeviceObject, PIRP Irp);
void __stdcall flush_thread(void* context);
NTSTATUS __stdcall io_completion(PDEVICE_OBJECT, PIRP Irp, PVOID ctx);
void do_xor(uint8_t* buf1, uint8_t* buf2, uint32_t len);

// pnp.cpp
NTSTATUS drv_pnp(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS __stdcall AddDevice(PDRIVER_OBJECT DriverObject, PDEVICE_OBJECT PhysicalDeviceObject);

// raid0.cpp
NTSTATUS read_raid0(set_pdo* pdo, PIRP Irp, bool* no_complete);
NTSTATUS write_raid0(set_pdo* pdo, PIRP Irp, bool* no_complete);

// raid1.cpp
NTSTATUS read_raid1(set_pdo* pdo, PIRP Irp, bool* no_complete);
NTSTATUS write_raid1(set_pdo* pdo, PIRP Irp);

class io_context {
public:
    io_context() { }

    io_context(set_child* sc, uint64_t stripe_start, uint64_t stripe_end) : sc(sc), stripe_start(stripe_start), stripe_end(stripe_end) {
        Irp = IoAllocateIrp(sc->device->StackSize, false);
        if (!Irp) {
            ERR("out of memory\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            return;
        }

        Irp->UserIosb = &iosb;

        KeInitializeEvent(&Event, NotificationEvent, false);
        Irp->UserEvent = &Event;

        IoSetCompletionRoutine(Irp, io_completion, this, true, true, true);

        Status = STATUS_SUCCESS;
    }

    ~io_context() {
        if (mdl)
            IoFreeMdl(mdl);

        if (va)
            ExFreePool(va);

        if (Irp)
            IoFreeIrp(Irp);
    }

    PIRP Irp = nullptr;
    KEVENT Event;
    IO_STATUS_BLOCK iosb;
    NTSTATUS Status;
    set_child* sc;
    uint64_t stripe_start;
    uint64_t stripe_end;
    void* va = nullptr;
    void* va2;
    PMDL mdl = nullptr;
    uint8_t* addr;
    PFN_NUMBER* pfns;
    PFN_NUMBER* pfnp;
    bool first;
    uint64_t stripe_pos;
    LIST_ENTRY list_entry;
};
