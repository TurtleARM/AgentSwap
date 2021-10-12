//
//  kernel_utils.c
//  agentSwap
//
//  Created by Davide Ornaghi on 19/09/21.
//
#include <CoreFoundation/CoreFoundation.h>
#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>

#include "../headers/common.h"
#include "../headers/iokit.h"
#include "../kern_utils/kernel_ops.h"
#include <sys/mount.h>
#include <sys/stat.h>
#include <dirent.h>
#include "kernel_utils.h"
#include "KernelOffsets.h"
#include "../offset-cache/offsetcache.h"
#include "../patchfinder/patchfinder64.h"

#define _assert(test) do { \
    if (test) break; \
    int saved_errno = errno; \
    LOG("_assert(%d:%s)@%s:%u[%s]", saved_errno, #test, __FILENAME__, __LINE__, __FUNCTION__); \
    errno = saved_errno; \
    goto out; \
} while(false)

#define setoffset(offset, val) set_offset(#offset, val)
#define getoffset(offset) get_offset(#offset)
#define CS_DYLD_PLATFORM 0x2000000 /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY 0x4000000 /* this is a platform binary */

#define TF_PLATFORM 0x00000400

kptr_t cached_proc_struct_addr = KPTR_NULL;
kptr_t kernel_base = KPTR_NULL;

// Trust cache types
typedef char hash_t[20];
int (*pmap_load_trust_cache)(kptr_t kernel_trust, size_t length) = NULL;

kptr_t get_address_of_port(kptr_t proc, mach_port_t port)
{
    kptr_t ret = KPTR_NULL;
    _assert(KERN_POINTER_VALID(proc));
    _assert(MACH_PORT_VALID(port));
    kptr_t const task_addr = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    _assert(KERN_POINTER_VALID(task_addr));
    kptr_t const itk_space = ReadKernel64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
    _assert(KERN_POINTER_VALID(itk_space));
    kptr_t const is_table = ReadKernel64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
    _assert(KERN_POINTER_VALID(is_table));
    kptr_t const port_addr = ReadKernel64(is_table + (MACH_PORT_INDEX(port) * koffset(KSTRUCT_SIZE_IPC_ENTRY)));
    _assert(KERN_POINTER_VALID(port_addr));
    ret = port_addr;
out:;
    return ret;
}

struct trust_chain {
    uint64_t next;
    unsigned char uuid[16];
    unsigned int count;
} __attribute__((packed));

uint32_t swap_uint32( uint32_t val ) {
    val = ((val << 8) & 0xFF00FF00 ) | ((val >> 8) & 0xFF00FF );
    return (val << 16) | (val >> 16);
}

uint8_t *getCodeDirectory(const char* name) {
    // Assuming it is a macho
    
    FILE* fd = fopen(name, "r");
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, fd);
    fseek(fd, 0, SEEK_SET);
    
    long off;
    int ncmds;
    
    if (magic == MH_MAGIC_64) {
        struct mach_header_64 mh64;
        fread(&mh64, sizeof(mh64), 1, fd);
        off = sizeof(mh64);
        ncmds = mh64.ncmds;
    } else if (magic == MH_MAGIC) {
        struct mach_header mh;
        fread(&mh, sizeof(mh), 1, fd);
        off = sizeof(mh);
        ncmds = mh.ncmds;
    } else {
        printf("%s is not a macho! (or has foreign endianness?) (magic: %x)\n", name, magic);
        return NULL;
    }
    
    for (int i = 0; i < ncmds; i++) {
        struct load_command cmd;
        fseek(fd, off, SEEK_SET);
        fread(&cmd, sizeof(struct load_command), 1, fd);
        if (cmd.cmd == LC_CODE_SIGNATURE) {
            uint32_t off_cs;
            fread(&off_cs, sizeof(uint32_t), 1, fd);
            uint32_t size_cs;
            fread(&size_cs, sizeof(uint32_t), 1, fd);
            
            uint8_t *cd = malloc(size_cs);
            fseek(fd, off_cs, SEEK_SET);
            fread(cd, size_cs, 1, fd);
            return cd;
        } else {
            off += cmd.cmdsize;
        }
    }
    return NULL;
}

uint64_t kalloc(vm_size_t size) {
    mach_vm_address_t address = 0;
    mach_vm_allocate(tfp0, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    return address;
}

kptr_t get_kernel_proc_struct_addr() {
    kptr_t ret = KPTR_NULL;
    kptr_t const symbol = getoffset(kernel_task);
    _assert(KERN_POINTER_VALID(symbol));
    kptr_t const task = ReadKernel64(symbol);
    _assert(KERN_POINTER_VALID(task));
    kptr_t const bsd_info = ReadKernel64(task + koffset(KSTRUCT_OFFSET_TASK_BSD_INFO));
    _assert(KERN_POINTER_VALID(bsd_info));
    ret = bsd_info;
out:;
    return ret;
}

bool iterate_proc_list(void (^handler)(kptr_t, pid_t, bool *)) {
    bool ret = false;
    _assert(handler != NULL);
    bool iterate = true;
    kptr_t proc = get_kernel_proc_struct_addr();
    _assert(KERN_POINTER_VALID(proc));
    while (KERN_POINTER_VALID(proc) && iterate) {
        pid_t const pid = ReadKernel32(proc + koffset(KSTRUCT_OFFSET_PROC_PID));
        handler(proc, pid, &iterate);
        if (!iterate) break;
        proc = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_P_LIST) + sizeof(kptr_t));
    }
    ret = true;
out:;
    return ret;
}

kptr_t get_proc_struct_for_pid(pid_t pid)
{
    __block kptr_t proc = KPTR_NULL;
    void (^const handler)(kptr_t, pid_t, bool *) = ^(kptr_t found_proc, pid_t found_pid, bool *iterate) {
        if (found_pid == pid) {
            proc = found_proc;
            *iterate = false;
        }
    };
    _assert(iterate_proc_list(handler));
out:;
    return proc;
}

kptr_t proc_struct_addr()
{
    kptr_t ret = KPTR_NULL;
    if (KERN_POINTER_VALID((ret = cached_proc_struct_addr))) goto out;
    cached_proc_struct_addr = get_proc_struct_for_pid(getpid());
out:;
    return cached_proc_struct_addr;
}

bool set_host_type(host_t host, uint32_t type) {
    bool ret = false;
    _assert(MACH_PORT_VALID(host));
    kptr_t const hostport_addr = get_address_of_port(proc_struct_addr(), host);
    _assert(KERN_POINTER_VALID(hostport_addr));
    _assert(WriteKernel32(hostport_addr, type));
    ret = true;
out:;
    return ret;
}

bool export_tfp0(host_t host) {
    bool ret = false;
    _assert(MACH_PORT_VALID(host));
    uint32_t const type = IO_BITS_ACTIVE | IKOT_HOST_PRIV;
    _assert(set_host_type(host, type));
    ret = true;
out:;
    return ret;
}

bool set_platform_binary(kptr_t proc, bool set)
{
    bool ret = false;
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const task_struct_addr = ReadKernel64(proc + koffset(KSTRUCT_OFFSET_PROC_TASK));
    _assert(KERN_POINTER_VALID(task_struct_addr));
    kptr_t const task_t_flags_addr = task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS);
    uint32_t task_t_flags = ReadKernel32(task_t_flags_addr);
    if (set) {
        task_t_flags |= TF_PLATFORM;
    } else {
        task_t_flags &= ~(TF_PLATFORM);
    }
    _assert(WriteKernel32(task_struct_addr + koffset(KSTRUCT_OFFSET_TASK_TFLAGS), task_t_flags));
    ret = true;
out:;
    return ret;
}

bool set_csflags(kptr_t proc, uint32_t flags, bool value) {
    bool ret = false;
    _assert(KERN_POINTER_VALID(proc));
    kptr_t const proc_csflags_addr = proc + koffset(KSTRUCT_OFFSET_PROC_P_CSFLAGS);
    uint32_t csflags = ReadKernel32(proc_csflags_addr);
    if (value == true) {
        csflags |= flags;
    } else {
        csflags &= ~flags;
    }
    _assert(WriteKernel32(proc_csflags_addr, csflags));
    ret = true;
out:;
    return ret;
}

bool set_cs_platform_binary(kptr_t proc, bool value) {
    bool ret = false;
    _assert(KERN_POINTER_VALID(proc));
    _assert(set_csflags(proc, CS_PLATFORM_BINARY, value));
    ret = true;
out:;
    return ret;
}
