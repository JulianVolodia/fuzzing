/*
 * GDI+ Image Fuzzer for Windows
 *
 * This fuzzer targets Windows GDI+ image parsing, a frequent source
 * of vulnerabilities in Windows. GDI+ handles multiple image formats
 * and is used throughout Windows for image rendering.
 *
 * Target areas:
 * - PNG, JPEG, GIF, BMP, TIFF parsing
 * - Image format conversions
 * - Metadata handling
 * - Graphics operations
 *
 * Past CVEs: CVE-2020-0618, CVE-2020-1425, CVE-2021-24092
 */

#include <windows.h>
#include <gdiplus.h>
#include <stdint.h>
#include <stddef.h>

#pragma comment(lib, "gdiplus.lib")

using namespace Gdiplus;

// Global GDI+ token for initialization
static ULONG_PTR gdiplusToken = 0;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // Initialize GDI+
    GdiplusStartupInput gdiplusStartupInput;
    GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 10 || Size > 10000000) {  // Prevent excessive memory usage
        return 0;
    }

    // Create a stream from memory
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, Size);
    if (!hMem) {
        return 0;
    }

    void* pMem = GlobalLock(hMem);
    if (!pMem) {
        GlobalFree(hMem);
        return 0;
    }

    memcpy(pMem, Data, Size);
    GlobalUnlock(hMem);

    IStream* pStream = NULL;
    if (CreateStreamOnHGlobal(hMem, TRUE, &pStream) != S_OK) {
        GlobalFree(hMem);
        return 0;
    }

    // Try to load the image
    Image* image = Image::FromStream(pStream);

    if (image && image->GetLastStatus() == Ok) {
        // Get image properties
        UINT width = image->GetWidth();
        UINT height = image->GetHeight();

        // Prevent excessive operations on huge images
        if (width < 10000 && height < 10000) {
            // Get pixel format
            PixelFormat format = image->GetPixelFormat();

            // Get image type
            ImageType type = image->GetType();

            // Test thumbnail generation
            Image* thumbnail = image->GetThumbnailImage(100, 100, NULL, NULL);
            if (thumbnail) {
                delete thumbnail;
            }

            // Get property items count
            UINT propCount = image->GetPropertyCount();
            if (propCount > 0 && propCount < 1000) {
                UINT propSize = image->GetPropertySize();
                if (propSize < 100000) {  // Prevent excessive allocation
                    // Test property item access (EXIF, etc.)
                    PropertyItem* items = (PropertyItem*)malloc(propSize);
                    if (items) {
                        if (image->GetAllPropertyItems(propSize, propCount, items) == Ok) {
                            // Successfully parsed metadata
                        }
                        free(items);
                    }
                }
            }

            // Test format conversion
            if (width < 1000 && height < 1000) {
                Bitmap* bitmap = new Bitmap(width, height, PixelFormat32bppARGB);
                if (bitmap) {
                    Graphics* graphics = Graphics::FromImage(bitmap);
                    if (graphics) {
                        // Draw the image (tests decoding)
                        graphics->DrawImage(image, 0, 0, width, height);
                        delete graphics;
                    }
                    delete bitmap;
                }
            }

            // Test getting encoder/decoder info
            UINT numEncoders = 0;
            UINT sizeEncoders = 0;
            GetImageEncodersSize(&numEncoders, &sizeEncoders);

            // Test frame dimensions
            UINT frameCount = image->GetFrameDimensionsCount();
            if (frameCount > 0 && frameCount < 100) {
                GUID* dimensionIDs = new GUID[frameCount];
                if (dimensionIDs) {
                    image->GetFrameDimensionsList(dimensionIDs, frameCount);

                    // Get frame count for first dimension
                    UINT frames = image->GetFrameCount(&dimensionIDs[0]);

                    // Test selecting different frames (for multi-frame images like GIF)
                    if (frames > 1 && frames < 100) {
                        image->SelectActiveFrame(&dimensionIDs[0], 0);
                    }

                    delete[] dimensionIDs;
                }
            }
        }

        delete image;
    }

    pStream->Release();
    // hMem is freed by the stream

    return 0;
}
