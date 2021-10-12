//
//  kpatches.c
//  agentSwap
//
//  Created by Davide Ornaghi on 20/09/21.
//

#include "kpatches.h"
#import "headers/common.h"
#include "machswap/machswap_pwn.h"
#import "kern_utils/kernel_ops.h"
#import "kern_utils/kernel_utils.h"
#import "jailbreak.h"
#import "patchfinder/patchfinder64.h"
#include <pwd.h>


/*bool get_root() {
    struct passwd *const root_pw = getpwnam("root");
    
    pid_t myPid = getppid();
    kptr_t myProc = 0;
    kptr_t _allproc = find_allproc();
    if (_allproc == 0) {
        LOG("Error getting _allproc offset");
        return false;
    }
    kptr_t p1 = ReadKernel64(_allproc);
    LOG("Found proc->next %p", p1);
    kptr_t p2 = ReadKernel64(_allproc + 8);
    LOG("Found proc->prev %p", p2);
    pid_t currentPid;
    kptr_t currentProc = _allproc;

    while (currentProc != 0) {
        currentPid = ReadKernel32(currentProc + 0x10); // p_pid
        //LOG("Found process with pid: %d", currentPid);
        if (currentPid == myPid) {
            LOG("Found process with the same pid: %d", currentPid);
            myProc = currentProc;
        }
        currentProc = ReadKernel64(currentProc + 0); // -> prev
    }
    if (myProc == 0) {
        LOG("Could not find this process in kernel");
        return false;
    }
    
    kptr_t credentials = ReadKernel64(myProc + 0x100); // ucred struct
    
    uint32_t uid = ReadKernel32(credentials + 0x18);
    LOG("Found UID: %d", uid);
    WriteKernel32(credentials + 0x18, 0); // cr_uid
    
    uid = ReadKernel32(credentials + 0x1c);
    LOG("Found RUID: %d", uid);
    WriteKernel32(credentials + 0x1c, 0); // cr_ruid
    
    uid = ReadKernel32(credentials + 0x20);
    LOG("Found SVUID: %d", uid);
    WriteKernel32(credentials + 0x20, 0); // cr_svuid
    
    uid = ReadKernel32(credentials + 0x68);
    LOG("Found RGID: %d", uid);
    WriteKernel32(credentials + 0x68, 0); // cr_rgid
    
    uid = ReadKernel32(credentials + 0x6c);
    LOG("Found SVGID: %d", uid);
    WriteKernel32(credentials + 0x6c, 0); // cr_svgid
    
    if (setuid(root_pw->pw_uid) != ERR_SUCCESS) {
        LOG("Cannot set creds");
        return false;
    }
    return true;
}
*/

void setCredentials(kptr_t p1, kptr_t p2) {
    kptr_t credentials2 = ReadKernel64(p2 + 0x100);
    LOG("Found creds at %p", credentials2);
    WriteKernel64(p1 + 0x100, credentials2);
}

void no_shenanigans() {
    uint64_t dummyPtr = 0xfeedcafebabe;
    kptr_t ktaskCheck = find_shenanigans();
    WriteKernel64(ktaskCheck, dummyPtr);
}

bool get_root() {
    struct passwd *const root_pw = getpwnam("root");
    
    pid_t myPid = getpid();
    kptr_t kernProc = 0;
    kptr_t myProc = 0;
    kptr_t _allproc = find_allproc();
    if (_allproc == 0) {
        LOG("Error getting _allproc offset");
        return false;
    }
    kptr_t p1 = ReadKernel64(_allproc);
    LOG("Found proc->next %p", p1);
    kptr_t p2 = ReadKernel64(_allproc + 8);
    LOG("Found proc->prev %p", p2);
    pid_t currentPid;
    kptr_t currentProc = _allproc;
    
    while (currentProc != 0) {
        currentPid = ReadKernel32(currentProc + 0x10); // p_pid
        //LOG("Found process with pid: %d", currentPid);
        if (currentPid == 0) {
            LOG("Got kernel process");
            kernProc = currentProc;
        }
        if (currentPid == myPid) {
            LOG("Got current process");
            myProc = currentProc;
        }
        currentProc = ReadKernel64(currentProc + 0); // -> next
    }
    if (kernProc == 0 || myProc == 0) {
        LOG("Could not find some processes");
        return false;
    }
    
    setCredentials(myProc, kernProc);

    kptr_t credentials = ReadKernel64(myProc + 0x100); // ucred struct
    uint32_t uid = ReadKernel32(credentials + 0x18);
    LOG("Current process UID: %d", uid);
    
    if (setuid(root_pw->pw_uid) != ERR_SUCCESS) {
        LOG("Cannot set creds");
        return false;
    }
    
    if (set_platform_binary(myProc, true) != true || set_cs_platform_binary(myProc, true) != true) {
        LOG("Error adding platform entitlements");
        return false;
    }
    
    
    return true;
}
