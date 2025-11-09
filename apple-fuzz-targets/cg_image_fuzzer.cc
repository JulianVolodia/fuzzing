/*
 * CoreGraphics/ImageIO Fuzzer
 *
 * This fuzzer targets Apple's image parsing frameworks.
 * Image parsers are notorious for vulnerabilities due to complex
 * file formats and extensive attack surface.
 *
 * Target areas:
 * - PNG, JPEG, HEIF, GIF, TIFF, and other image format parsers
 * - Image metadata (EXIF, XMP, IPTC)
 * - Thumbnail generation
 * - Color space handling
 */

#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 10) {
        return 0;
    }

    // Create a CFData object from the input
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, Data, Size);
    if (!data) {
        return 0;
    }

    // Create an image source from the data
    CGImageSourceRef imageSource = CGImageSourceCreateWithData(data, NULL);

    if (imageSource) {
        // Get image count
        size_t count = CGImageSourceGetCount(imageSource);

        if (count > 0 && count < 100) {  // Prevent excessive memory usage
            // Get image type
            CFStringRef type = CGImageSourceGetType(imageSource);
            if (type) {
                CFRelease(type);
            }

            // Get properties for first image
            CFDictionaryRef properties = CGImageSourceCopyPropertiesAtIndex(imageSource, 0, NULL);
            if (properties) {
                CFRelease(properties);
            }

            // Try to create the image
            CGImageRef image = CGImageSourceCreateImageAtIndex(imageSource, 0, NULL);
            if (image) {
                // Get image properties
                size_t width = CGImageGetWidth(image);
                size_t height = CGImageGetHeight(image);
                size_t bitsPerComponent = CGImageGetBitsPerComponent(image);
                size_t bitsPerPixel = CGImageGetBitsPerPixel(image);

                // Prevent excessive memory allocation
                if (width < 10000 && height < 10000) {
                    // Get color space
                    CGColorSpaceRef colorSpace = CGImageGetColorSpace(image);

                    // Get alpha info
                    CGImageAlphaInfo alphaInfo = CGImageGetAlphaInfo(image);
                    (void)alphaInfo;

                    // Try to create a thumbnail
                    CFDictionaryRef options = CFDictionaryCreate(
                        kCFAllocatorDefault,
                        NULL, NULL, 0,
                        &kCFTypeDictionaryKeyCallBacks,
                        &kCFTypeDictionaryValueCallBacks
                    );

                    if (options) {
                        CGImageRef thumbnail = CGImageSourceCreateThumbnailAtIndex(
                            imageSource, 0, options
                        );
                        if (thumbnail) {
                            CFRelease(thumbnail);
                        }
                        CFRelease(options);
                    }
                }

                CFRelease(image);
            }
        }

        CFRelease(imageSource);
    }

    // Also test incremental loading
    CGImageSourceRef incrementalSource = CGImageSourceCreateIncremental(NULL);
    if (incrementalSource) {
        CGImageSourceUpdateData(incrementalSource, data, false);

        // Check status
        CGImageSourceStatus status = CGImageSourceGetStatus(incrementalSource);

        if (status != kCGImageStatusInvalidData) {
            // Try to get partial image
            CGImageRef partialImage = CGImageSourceCreateImageAtIndex(incrementalSource, 0, NULL);
            if (partialImage) {
                CFRelease(partialImage);
            }
        }

        // Finalize
        CGImageSourceUpdateData(incrementalSource, data, true);
        CFRelease(incrementalSource);
    }

    CFRelease(data);
    return 0;
}
