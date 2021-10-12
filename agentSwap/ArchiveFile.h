//
//  Archive.h
//
//  Created by Sam Bingner on 1/4/19.
//  Copyright © 2019 Sam Bingner. All rights reserved.
//

#ifndef _ARCHIVE_FILE_H
#define _ARCHIVE_FILE_H
#import <Foundation/Foundation.h>
#import "headers/archive.h"


void write_archive(const char *outname, const char **filename);

#endif /* _ARCHIVE_FILE_H */
