/*
 *  inject.m
 *  
 *  Created by Sam Bingner on 9/27/2018
 *  Copyright 2018 Sam Bingner. All Rights Reserved.
 *
 */

#include <Foundation/Foundation.h>
#include <mach/mach.h>
#include <dlfcn.h>
#include "CSCommon.h"
#ifdef UNDECIMUS
#include <common.h>
#define INJECT_LOG(x, ...) LOG(x, ##__VA_ARGS__)
#define rk64(x) ReadKernel64(x)
#define wk64(x, y) WriteKernel64(x, y)
#else
#define INJECT_LOG(x, ...) printf(x "\n", ##__VA_ARGS__)
#endif
#include "kern_funcs.h"
#include "../kern_utils/kernel_ops.h"

OSStatus SecStaticCodeCreateWithPathAndAttributes(CFURLRef path, SecCSFlags flags, CFDictionaryRef attributes, SecStaticCodeRef  _Nullable *staticCode);
OSStatus SecCodeCopySigningInformation(SecStaticCodeRef code, SecCSFlags flags, CFDictionaryRef  _Nullable *information);
CFStringRef (*_SecCopyErrorMessageString)(OSStatus status, void * __nullable reserved) = NULL;
extern int MISValidateSignatureAndCopyInfo(NSString *file, NSDictionary *options, NSDictionary **info);

extern NSString *MISCopyErrorStringForErrorCode(int err);
extern NSString *kMISValidationOptionRespectUppTrustAndAuthorization;
extern NSString *kMISValidationOptionValidateSignatureOnly;
extern NSString *kMISValidationOptionUniversalFileOffset;
extern NSString *kMISValidationOptionAllowAdHocSigning;
extern NSString *kMISValidationOptionOnlineAuthorization;
 
enum cdHashType {
    cdHashTypeSHA1 = 1,
    cdHashTypeSHA256 = 2
};

static char *cdHashName[3] = {NULL, "SHA1", "SHA256"};

static enum cdHashType requiredHash = cdHashTypeSHA256;

#define TRUST_CDHASH_LEN (20)
 
struct trust_mem {
    uint64_t next; //struct trust_mem *next;
    unsigned char uuid[16];
    unsigned int count;
    //unsigned char data[];
} __attribute__((packed));

struct hash_entry_t {
    uint16_t num;
    uint16_t start;
} __attribute__((packed));

typedef uint8_t hash_t[TRUST_CDHASH_LEN];

bool isInAMFIStaticCache(NSString *path) {
    return MISValidateSignatureAndCopyInfo(path, @{kMISValidationOptionAllowAdHocSigning: @YES, kMISValidationOptionRespectUppTrustAndAuthorization: @YES}, NULL) == 0;
}

NSString *cdhashFor(NSString *file) {
    NSString *cdhash = nil;
    SecStaticCodeRef staticCode;
    OSStatus result = SecStaticCodeCreateWithPathAndAttributes(CFURLCreateWithFileSystemPath(kCFAllocatorDefault, (CFStringRef)file, kCFURLPOSIXPathStyle, false), kSecCSDefaultFlags, NULL, &staticCode);
    const char *filename = file.UTF8String;
    if (result != errSecSuccess) {
        if (_SecCopyErrorMessageString != NULL) {
            CFStringRef error = _SecCopyErrorMessageString(result, NULL);
            INJECT_LOG("Unable to generate cdhash for %s: %s", filename, [(__bridge id)error UTF8String]);
            CFRelease(error);
        } else {
            INJECT_LOG("Unable to generate cdhash for %s: %d", filename, result);
        }
        return nil;
    }
    
    CFDictionaryRef cfinfo;
    result = SecCodeCopySigningInformation(staticCode, kSecCSDefaultFlags, &cfinfo);
    NSDictionary *info = CFBridgingRelease(cfinfo);
    CFRelease(staticCode);
    if (result != errSecSuccess) {
        INJECT_LOG("Unable to copy cdhash info for %s", filename);
        return nil;
    }
    NSArray *cdhashes = info[@"cdhashes"];
    NSArray *algos = info[@"digest-algorithms"];
    NSUInteger algoIndex = [algos indexOfObject:@(requiredHash)];
    
    if (cdhashes == nil) {
        INJECT_LOG("%s: no cdhashes", filename);
    } else if (algos == nil) {
        INJECT_LOG("%s: no algos", filename);
    } else if (algoIndex == NSNotFound) {
        INJECT_LOG("%s: does not have %s hash", cdHashName[requiredHash], filename);
    } else {
        cdhash = [cdhashes objectAtIndex:algoIndex];
        if (cdhash == nil) {
            INJECT_LOG("%s: missing %s cdhash entry", file.UTF8String, cdHashName[requiredHash]);
        }
    }
    return cdhash;
}

NSArray *filteredHashes(uint64_t trust_chain, NSDictionary *hashes) {
#if !__has_feature(objc_arc)
  NSArray *result;
  @autoreleasepool {
#endif
      NSMutableDictionary *filtered = [hashes mutableCopy];
    for (NSData *cdhash in [filtered allKeys]) {
        if (isInAMFIStaticCache(filtered[cdhash])) {
            INJECT_LOG("%s: already in static trustcache, not reinjecting", [filtered[cdhash] UTF8String]);
            [filtered removeObjectForKey:cdhash];
        }
    }

    struct trust_mem search;
    search.next = trust_chain;
    while (search.next != 0) {
        uint64_t searchAddr = search.next;
        kread(searchAddr, &search, sizeof(struct trust_mem));
        //INJECT_LOG("Checking %d entries at 0x%llx", search.count, searchAddr);
        char *data = malloc(search.count * TRUST_CDHASH_LEN);
        kread(searchAddr + sizeof(struct trust_mem), data, search.count * TRUST_CDHASH_LEN);
        size_t data_size = search.count * TRUST_CDHASH_LEN;

        for (char *dataref = data; dataref <= data + data_size - TRUST_CDHASH_LEN; dataref += TRUST_CDHASH_LEN) {
            NSData *cdhash = [NSData dataWithBytesNoCopy:dataref length:TRUST_CDHASH_LEN freeWhenDone:NO];
            NSString *hashName = filtered[cdhash];
            if (hashName != nil) {
                INJECT_LOG("%s: already in dynamic trustcache, not reinjecting", [hashName UTF8String]);
                [filtered removeObjectForKey:cdhash];
                if ([filtered count] == 0) {
                    free(data);
                    return nil;
                }
            }
        }
        free(data);
    }
    INJECT_LOG("Actually injecting %lu keys", [[filtered allKeys] count]);
#if __has_feature(objc_arc)
    return [filtered allKeys];
#else
    result = [[filtered allKeys] retain];
  }
  return [result autorelease];
#endif
}

int injectTrustCache(NSArray <NSString*> *files, uint64_t trust_chain, int (*pmap_load_trust_cache)(uint64_t, size_t))
{
  @autoreleasepool {
    struct trust_mem mem;
    uint64_t kernel_trust = 0;

    mem.next = rk64(trust_chain);
    mem.count = 0;
    uuid_generate(mem.uuid);

    NSMutableDictionary *hashes = [NSMutableDictionary new];
    int errors=0;

    for (NSString *file in files) {
        NSString *cdhash = cdhashFor(file);
        if (cdhash == nil) {
            errors++;
            continue;
        }
        if (hashes[cdhash] == nil) {
            //INJECT_LOG("%s: OK", file.UTF8String);
            hashes[cdhash] = file;
        } else {
            INJECT_LOG("%s: same as %s (ignoring)", file.UTF8String, [hashes[cdhash] UTF8String]);
        }
    }
    unsigned numHashes = (unsigned)[hashes count];

    if (numHashes < 1) {
        INJECT_LOG("Found no hashes to inject");
        return errors;
    }


    NSArray *filtered = filteredHashes(mem.next, hashes);
    unsigned hashesToInject = (unsigned)[filtered count];
    INJECT_LOG("%u new hashes to inject", hashesToInject);
    if (hashesToInject < 1) {
        return errors;
    }

    size_t length = (32 + hashesToInject * TRUST_CDHASH_LEN + vm_kernel_page_size) & ~vm_kernel_page_size;
    char *buffer = malloc(hashesToInject * TRUST_CDHASH_LEN);
    if (buffer == NULL) {
        INJECT_LOG("Unable to allocate memory for cdhashes: %s", strerror(errno));
        return -3;
    }
    char *curbuf = buffer;
    for (NSData *hash in filtered) {
        memcpy(curbuf, [hash bytes], TRUST_CDHASH_LEN);
        curbuf += TRUST_CDHASH_LEN;
    }
    kernel_trust = kmem_alloc(length);

    mem.count = hashesToInject;
    kwrite(kernel_trust, &mem, sizeof(mem));
    kwrite(kernel_trust + sizeof(mem), buffer, mem.count * TRUST_CDHASH_LEN);
    if (pmap_load_trust_cache != NULL) {
      if (pmap_load_trust_cache(kernel_trust, length) != ERR_SUCCESS) {
        return -4;
      }
    } else {
        wk64(trust_chain, kernel_trust);
    }

    return (int)errors;
  }
}

__attribute__((constructor))
void ctor() {
    void *lib = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (lib != NULL) {
        _SecCopyErrorMessageString = dlsym(lib, "SecCopyErrorMessageString");
        dlclose(lib);
    }
}
