/*
 * Property List (plist) Fuzzer
 *
 * Property lists are used extensively in macOS/iOS for configuration
 * and data storage. Both XML and binary formats are supported.
 *
 * Target areas:
 * - XML property list parsing
 * - Binary property list parsing
 * - Property list serialization
 * - Type conversions and edge cases
 */

#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 4) {
        return 0;
    }

    // Create CFData from input
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, Data, Size);
    if (!data) {
        return 0;
    }

    CFErrorRef error = NULL;

    // Try to parse as property list
    CFPropertyListRef plist = CFPropertyListCreateWithData(
        kCFAllocatorDefault,
        data,
        kCFPropertyListImmutable,
        NULL,
        &error
    );

    if (plist) {
        // Test various property list operations
        CFPropertyListRef plistCopy = CFPropertyListCreateDeepCopy(
            kCFAllocatorDefault,
            plist,
            kCFPropertyListImmutable
        );

        if (plistCopy) {
            CFRelease(plistCopy);
        }

        // Try to serialize it back
        CFDataRef serialized = CFPropertyListCreateData(
            kCFAllocatorDefault,
            plist,
            kCFPropertyListXMLFormat_v1_0,
            0,
            &error
        );

        if (serialized) {
            CFRelease(serialized);
        }

        if (error) {
            CFRelease(error);
            error = NULL;
        }

        // Try binary format
        serialized = CFPropertyListCreateData(
            kCFAllocatorDefault,
            plist,
            kCFPropertyListBinaryFormat_v1_0,
            0,
            &error
        );

        if (serialized) {
            CFRelease(serialized);
        }

        if (error) {
            CFRelease(error);
            error = NULL;
        }

        // Test type checking
        CFTypeID typeID = CFGetTypeID(plist);

        if (typeID == CFDictionaryGetTypeID()) {
            CFDictionaryRef dict = (CFDictionaryRef)plist;
            CFIndex count = CFDictionaryGetCount(dict);

            if (count > 0 && count < 1000) {
                // Iterate through keys
                const void **keys = (const void **)malloc(sizeof(void *) * count);
                const void **values = (const void **)malloc(sizeof(void *) * count);

                if (keys && values) {
                    CFDictionaryGetKeysAndValues(dict, keys, values);
                    free(keys);
                    free(values);
                }
            }
        } else if (typeID == CFArrayGetTypeID()) {
            CFArrayRef array = (CFArrayRef)plist;
            CFIndex count = CFArrayGetCount(array);

            if (count > 0 && count < 1000) {
                for (CFIndex i = 0; i < count && i < 10; i++) {
                    CFTypeRef value = CFArrayGetValueAtIndex(array, i);
                    (void)value;
                }
            }
        }

        CFRelease(plist);
    }

    if (error) {
        CFRelease(error);
    }

    CFRelease(data);
    return 0;
}
