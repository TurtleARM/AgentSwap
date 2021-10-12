//
//  kernel_utils.h
//  agentSwap
//
//  Created by Davide Ornaghi on 19/09/21.
//

#ifndef kernel_utils_h
#define kernel_utils_h

#include <stdio.h>
#include "../headers/common.h"
#include <mach/mach.h>
#include "../offset-cache/offsetcache.h"
#include <stdbool.h>

extern kptr_t kernel_base;
extern uint64_t kernel_slide;

#define setoffset(offset, val) set_offset(#offset, val)
#define getoffset(offset) get_offset(#offset)

kptr_t get_kernel_proc_struct_addr(void);
kptr_t proc_struct_addr(void);
kptr_t get_kernel_proc_struct_addr(void);
bool export_tfp0(host_t host);
bool set_platform_binary(kptr_t proc, bool set);

bool set_csflags(kptr_t proc, uint32_t flags, bool value);
bool set_cs_platform_binary(kptr_t proc, bool value);

#endif /* kernel_utils_h */
