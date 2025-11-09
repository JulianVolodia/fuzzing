/*
 * CoreText Font Fuzzer
 *
 * Font parsing is a classic source of vulnerabilities. This fuzzer
 * targets Apple's CoreText framework for rendering text and handling fonts.
 *
 * Target areas:
 * - TrueType/OpenType font parsing
 * - Font descriptor creation
 * - Glyph rendering
 * - Font table parsing
 */

#include <CoreText/CoreText.h>
#include <CoreFoundation/CoreFoundation.h>
#include <CoreGraphics/CoreGraphics.h>
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 100) {  // Font files need minimum size
        return 0;
    }

    // Create CFData from input
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, Data, Size);
    if (!data) {
        return 0;
    }

    // Create a font descriptor from the data
    CGDataProviderRef dataProvider = CGDataProviderCreateWithCFData(data);

    if (dataProvider) {
        // Try to create a font from the data
        CGFontRef cgFont = CGFontCreateWithDataProvider(dataProvider);

        if (cgFont) {
            // Get font properties
            CFStringRef fontName = CGFontCopyFullName(cgFont);
            if (fontName) {
                CFRelease(fontName);
            }

            fontName = CGFontCopyPostScriptName(cgFont);
            if (fontName) {
                CFRelease(fontName);
            }

            // Get number of glyphs
            size_t numGlyphs = CGFontGetNumberOfGlyphs(cgFont);

            if (numGlyphs > 0 && numGlyphs < 100000) {
                // Get font bbox
                CGRect bbox = CGFontGetFontBBox(cgFont);
                (void)bbox;

                // Get units per em
                int unitsPerEm = CGFontGetUnitsPerEm(cgFont);
                (void)unitsPerEm;

                // Try to get advances for first few glyphs
                CGGlyph glyphs[10] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
                int advances[10];
                CGFontGetGlyphAdvances(cgFont, glyphs, 10, advances);

                // Get glyph bounding boxes
                CGRect bboxes[10];
                CGFontGetGlyphBBoxes(cgFont, glyphs, 10, bboxes);
            }

            // Create CTFont from CGFont
            CTFontRef ctFont = CTFontCreateWithGraphicsFont(cgFont, 12.0, NULL, NULL);
            if (ctFont) {
                // Get font metrics
                CGFloat ascent = CTFontGetAscent(ctFont);
                CGFloat descent = CTFontGetDescent(ctFont);
                CGFloat leading = CTFontGetLeading(ctFont);
                (void)ascent; (void)descent; (void)leading;

                // Get glyph count
                CFIndex glyphCount = CTFontGetGlyphCount(ctFont);

                if (glyphCount > 0 && glyphCount < 100000) {
                    // Try to get glyphs for characters
                    UniChar characters[5] = {'A', 'B', 'C', '1', '2'};
                    CGGlyph glyphs[5];
                    CTFontGetGlyphsForCharacters(ctFont, characters, glyphs, 5);
                }

                // Get font descriptor
                CTFontDescriptorRef descriptor = CTFontCopyFontDescriptor(ctFont);
                if (descriptor) {
                    CFRelease(descriptor);
                }

                CFRelease(ctFont);
            }

            CFRelease(cgFont);
        }

        CFRelease(dataProvider);
    }

    CFRelease(data);
    return 0;
}
