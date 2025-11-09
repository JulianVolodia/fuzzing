/*
 * DirectWrite Font Fuzzer for Windows
 *
 * This fuzzer targets Windows DirectWrite font rendering API.
 * Font parsing is a classic vulnerability source due to complex
 * table structures and extensive processing.
 *
 * Target areas:
 * - TrueType/OpenType font parsing
 * - Font face creation
 * - Glyph metrics and rendering
 * - Font collections
 *
 * Past CVEs: CVE-2020-1020, CVE-2021-26415
 */

#include <windows.h>
#include <dwrite.h>
#include <d2d1.h>
#include <stdint.h>
#include <stddef.h>

#pragma comment(lib, "dwrite.lib")
#pragma comment(lib, "d2d1.lib")

static IDWriteFactory* g_pDWriteFactory = NULL;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // Initialize COM
    CoInitialize(NULL);

    // Create DirectWrite factory
    DWriteCreateFactory(
        DWRITE_FACTORY_TYPE_SHARED,
        __uuidof(IDWriteFactory),
        reinterpret_cast<IUnknown**>(&g_pDWriteFactory)
    );

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!g_pDWriteFactory || Size < 100 || Size > 10000000) {
        return 0;
    }

    // Create a font file stream
    IDWriteFontFileStream* fontFileStream = NULL;
    IDWriteFontFile* fontFile = NULL;
    IDWriteFontFace* fontFace = NULL;

    // Create custom font loader (in-memory)
    // For simplicity, we'll use the system font loader with a temporary file
    // In production fuzzing, implement a custom loader for in-memory fonts

    // Write to temporary file
    wchar_t tempPath[MAX_PATH];
    wchar_t tempFile[MAX_PATH];

    GetTempPathW(MAX_PATH, tempPath);
    GetTempFileNameW(tempPath, L"fnt", 0, tempFile);

    HANDLE hFile = CreateFileW(
        tempFile,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE,
        NULL
    );

    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        WriteFile(hFile, Data, (DWORD)Size, &written, NULL);
        CloseHandle(hFile);

        // Create font file reference
        HRESULT hr = g_pDWriteFactory->CreateFontFileReference(
            tempFile,
            NULL,
            &fontFile
        );

        if (SUCCEEDED(hr) && fontFile) {
            // Analyze font file
            BOOL isSupportedFontType;
            DWRITE_FONT_FILE_TYPE fontFileType;
            DWRITE_FONT_FACE_TYPE fontFaceType;
            UINT32 numberOfFaces;

            hr = fontFile->Analyze(
                &isSupportedFontType,
                &fontFileType,
                &fontFaceType,
                &numberOfFaces
            );

            if (SUCCEEDED(hr) && isSupportedFontType && numberOfFaces > 0) {
                // Create font face
                IDWriteFontFile* fontFiles[] = { fontFile };

                hr = g_pDWriteFactory->CreateFontFace(
                    fontFaceType,
                    1,
                    fontFiles,
                    0,  // face index
                    DWRITE_FONT_SIMULATIONS_NONE,
                    &fontFace
                );

                if (SUCCEEDED(hr) && fontFace) {
                    // Get font metrics
                    DWRITE_FONT_METRICS fontMetrics;
                    fontFace->GetMetrics(&fontMetrics);

                    // Get glyph count
                    UINT16 glyphCount = fontFace->GetGlyphCount();

                    if (glyphCount > 0 && glyphCount < 100000) {
                        // Test getting glyph indices
                        UINT32 codePoints[] = { 'A', 'B', 'C', '1', '2', '3' };
                        UINT16 glyphIndices[6];

                        fontFace->GetGlyphIndices(codePoints, 6, glyphIndices);

                        // Get design glyph metrics
                        DWRITE_GLYPH_METRICS glyphMetrics[6];
                        fontFace->GetDesignGlyphMetrics(glyphIndices, 6, glyphMetrics, FALSE);

                        // Get glyph run outline (tests glyph data parsing)
                        // This would require implementing ID2D1SimplifiedGeometrySink
                        // Skipping for brevity, but this is where deep parsing happens

                        // Test font properties
                        IDWriteFontFace1* fontFace1 = NULL;
                        if (SUCCEEDED(fontFace->QueryInterface(&fontFace1))) {
                            // Get more detailed metrics
                            DWRITE_FONT_METRICS1 fontMetrics1;
                            fontFace1->GetMetrics(&fontMetrics1);

                            // Test Unicode ranges
                            UINT32 maxRangeCount = 0;
                            fontFace1->GetUnicodeRanges(0, NULL, &maxRangeCount);

                            if (maxRangeCount > 0 && maxRangeCount < 1000) {
                                DWRITE_UNICODE_RANGE* ranges = new DWRITE_UNICODE_RANGE[maxRangeCount];
                                UINT32 actualRangeCount;
                                fontFace1->GetUnicodeRanges(maxRangeCount, ranges, &actualRangeCount);
                                delete[] ranges;
                            }

                            fontFace1->Release();
                        }
                    }

                    fontFace->Release();
                }
            }

            fontFile->Release();
        }

        DeleteFileW(tempFile);
    }

    return 0;
}
