/*
 * Archive Fuzzer
 *
 * This fuzzer targets libarchive, which is used by macOS for handling
 * various archive formats (ZIP, TAR, etc.). Archive parsers are complex
 * and often contain vulnerabilities.
 *
 * Target areas:
 * - ZIP file parsing
 * - TAR file parsing
 * - Compression handling (gzip, bzip2, xz, etc.)
 * - Path traversal vulnerabilities
 * - Symlink handling
 */

#include <archive.h>
#include <archive_entry.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 10) {
        return 0;
    }

    // Create a read archive
    struct archive *a = archive_read_new();
    if (!a) {
        return 0;
    }

    // Enable all formats and filters
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    // Set options to prevent excessive resource usage
    archive_read_set_option(a, NULL, "hdrcharset", "UTF-8");

    // Open archive from memory
    int r = archive_read_open_memory(a, (void *)Data, Size);

    if (r == ARCHIVE_OK) {
        struct archive_entry *entry;

        // Read entries (limit to prevent DoS)
        int entry_count = 0;
        const int MAX_ENTRIES = 100;

        while (archive_read_next_header(a, &entry) == ARCHIVE_OK && entry_count < MAX_ENTRIES) {
            entry_count++;

            // Get entry properties
            const char *pathname = archive_entry_pathname(entry);
            if (pathname) {
                size_t path_len = strlen(pathname);
                (void)path_len;
            }

            int64_t size = archive_entry_size(entry);
            mode_t mode = archive_entry_mode(entry);
            time_t mtime = archive_entry_mtime(entry);
            (void)size; (void)mode; (void)mtime;

            // Get file type
            __LA_MODE_T filetype = archive_entry_filetype(entry);
            (void)filetype;

            // Try to read some data (limit to prevent excessive memory usage)
            const size_t READ_SIZE = 4096;
            if (size > 0 && size < READ_SIZE * 10) {
                char buffer[READ_SIZE];
                ssize_t bytes_read;

                bytes_read = archive_read_data(a, buffer, sizeof(buffer));
                (void)bytes_read;
            } else {
                // Skip large files
                archive_read_data_skip(a);
            }

            // Test entry cloning
            struct archive_entry *entry_copy = archive_entry_clone(entry);
            if (entry_copy) {
                archive_entry_free(entry_copy);
            }
        }
    }

    // Clean up
    archive_read_free(a);

    // Also test write functionality (round-trip)
    if (Size > 100 && Size < 10000) {
        struct archive *write_archive = archive_write_new();
        if (write_archive) {
            archive_write_set_format_pax_restricted(write_archive);
            archive_write_add_filter_gzip(write_archive);

            // Write to memory
            size_t buffer_size = Size * 2;
            char *buffer = (char *)malloc(buffer_size);
            if (buffer) {
                archive_write_open_memory(write_archive, buffer, buffer_size, &buffer_size);

                // Create a simple entry
                struct archive_entry *entry = archive_entry_new();
                if (entry) {
                    archive_entry_set_pathname(entry, "test.txt");
                    archive_entry_set_size(entry, Size);
                    archive_entry_set_filetype(entry, AE_IFREG);
                    archive_entry_set_perm(entry, 0644);

                    archive_write_header(write_archive, entry);
                    archive_write_data(write_archive, Data, Size);

                    archive_entry_free(entry);
                }

                archive_write_close(write_archive);
                free(buffer);
            }

            archive_write_free(write_archive);
        }
    }

    return 0;
}
