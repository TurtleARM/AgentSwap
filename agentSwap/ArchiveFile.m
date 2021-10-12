//
//  Archive.m
//
//  Created by Sam Bingner on 1/4/19.
//  Copyright © 2019 Sam Bingner. All rights reserved.
//

#import "ArchiveFile.h"
#import "headers/archive.h"
#import "headers/archive_entry.h"
#import <dirent.h>
#import "headers/common.h"

void file_to_archive(struct archive *a, const char *name) {
    char buffer[8192];
    size_t bytes_read;
    struct archive *ard;
    struct archive_entry *entry;
    int fd;
    ard = archive_read_disk_new();
    archive_read_disk_set_standard_lookup(ard);
    entry = archive_entry_new();
    fd = open(name, O_RDONLY);
    if (fd < 0)
        return;
/*      struct stat st;
        if (fstat(fd, &st) != 0) {
            LOG("Cannot stat original file");
        } else {
        archive_write_set_skip_file(a, st.st_dev, st.st_ino);
*/
    archive_entry_copy_pathname(entry, name);
    archive_read_disk_entry_from_file(ard, entry, fd, NULL);
    archive_write_header(a, entry);
    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0)
        archive_write_data(a, buffer, bytes_read);
    archive_write_finish_entry(a);
    archive_read_finish(ard);
    archive_entry_free(entry);
    //archive_read_close(ard);
    //archive_read_free(ard);
}

void write_archive(const char *outname, const char **filename) {
    struct archive *a;
    a = archive_write_new();
    archive_write_set_format_zip(a);
    archive_write_open_filename(a, outname);

    while(*filename) {
        file_to_archive(a, *filename);
        filename++;
    }
    
    archive_write_finish(a);
}
