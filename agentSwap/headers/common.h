//
//  common.h
//  agentSwap
//
//  Created by Davide Ornaghi on 19/09/21.
//

#ifndef common_h
#define common_h

#include <stdint.h>
#include <stdbool.h>
#include <mach-o/loader.h>
#include <mach/error.h>
#ifdef __OBJC__
#include <Foundation/Foundation.h>
#define RAWLOG(str, args...) do { NSLog(@str, ##args); } while(false)
#define ADDRSTRING(val) [NSString stringWithFormat:@ADDR, val]
#else
#include <CoreFoundation/CoreFoundation.h>
extern void NSLog(CFStringRef, ...);
#define RAWLOG(str, args...) do { NSLog(CFSTR(str), ##args); } while(false)
#define BOOL bool
#define YES ((BOOL) true)
#define NO ((BOOL) false)
#endif


#define LOG(str, args...) RAWLOG("[*] " str, ##args)
#define KERN_POINTER_VALID(val) ((val) >= 0xffff000000000000 && (val) != 0xffffffffffffffff)
typedef uint64_t kptr_t;
#define KPTR_NULL ((kptr_t) 0)
#define MAX_KASLR_SLIDE 0x21000000
#define STATIC_KERNEL_BASE_ADDRESS 0xfffffff007004000
#define ADDR                 "0x%016llx"
#define MACH_HEADER_MAGIC    MH_MAGIC_64
#define __FILENAME__ (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#define kCFCoreFoundationVersionNumber_iOS_12_0 1535.12
#define kCFCoreFoundationVersionNumber_iOS_11_3 1452.23
#define kCFCoreFoundationVersionNumber_iOS_11_0 1443.00

#endif /* common_h */
