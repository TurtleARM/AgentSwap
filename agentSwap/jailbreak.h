//
//  jailbreak.h
//  agentSwap
//
//  Created by Davide Ornaghi on 19/09/21.
//


#ifndef jailbreak_h
#define jailbreak_h

void get_tfp0(void);
void kpatch(void);
void extract(void);
void extractArchive(const char *path, char* outArchive);
void archive(void);
bool patch_kernel(void);
void write_hashes(const char* path);

#endif /* jailbreak_h */
