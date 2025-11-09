/*
 * CoreFoundation String Fuzzer
 *
 * This fuzzer targets Apple's CoreFoundation string handling APIs.
 * CFString is used extensively throughout macOS and iOS, making it
 * a high-value target for vulnerability research.
 *
 * Target areas:
 * - String creation from various encodings
 * - String conversion and transformation
 * - Edge cases in encoding handling
 */

#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 2) {
        return 0;
    }

    // Use first byte to select encoding
    CFStringEncoding encoding;
    switch (Data[0] % 10) {
        case 0: encoding = kCFStringEncodingUTF8; break;
        case 1: encoding = kCFStringEncodingUTF16; break;
        case 2: encoding = kCFStringEncodingUTF16BE; break;
        case 3: encoding = kCFStringEncodingUTF16LE; break;
        case 4: encoding = kCFStringEncodingUTF32; break;
        case 5: encoding = kCFStringEncodingMacRoman; break;
        case 6: encoding = kCFStringEncodingWindowsLatin1; break;
        case 7: encoding = kCFStringEncodingISOLatin1; break;
        case 8: encoding = kCFStringEncodingASCII; break;
        default: encoding = kCFStringEncodingUTF8; break;
    }

    const uint8_t *string_data = Data + 1;
    size_t string_size = Size - 1;

    // Test CFStringCreateWithBytes
    CFStringRef cfString = CFStringCreateWithBytes(
        kCFAllocatorDefault,
        string_data,
        string_size,
        encoding,
        false  // isExternalRepresentation
    );

    if (cfString) {
        // Test various string operations
        CFIndex length = CFStringGetLength(cfString);

        if (length > 0 && length < 10000) {
            // Test conversion to C string
            char buffer[1024];
            CFStringGetCString(cfString, buffer, sizeof(buffer), kCFStringEncodingUTF8);

            // Test character access
            if (length > 0) {
                UniChar ch = CFStringGetCharacterAtIndex(cfString, 0);
                (void)ch;
            }

            // Test string comparison
            CFStringRef testStr = CFSTR("test");
            CFComparisonResult result = CFStringCompare(cfString, testStr, 0);
            (void)result;
            CFRelease(testStr);

            // Test finding
            CFRange range = CFStringFind(cfString, CFSTR("test"), 0);
            (void)range;

            // Test case conversion
            CFMutableStringRef mutableStr = CFStringCreateMutableCopy(
                kCFAllocatorDefault, 0, cfString
            );
            if (mutableStr) {
                CFStringUppercase(mutableStr, NULL);
                CFStringLowercase(mutableStr, NULL);
                CFRelease(mutableStr);
            }
        }

        CFRelease(cfString);
    }

    // Test creating with external representation flag
    cfString = CFStringCreateWithBytes(
        kCFAllocatorDefault,
        string_data,
        string_size,
        encoding,
        true  // isExternalRepresentation
    );

    if (cfString) {
        CFRelease(cfString);
    }

    return 0;
}
