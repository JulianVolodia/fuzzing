/*
 * Windows Imaging Component (WIC) Fuzzer
 *
 * WIC is the modern imaging framework in Windows that provides
 * codec-independent access to image formats. It's used throughout
 * Windows for image operations.
 *
 * Target areas:
 * - Built-in and third-party codecs
 * - Image format detection
 * - Metadata handlers
 * - Thumbnail generation
 *
 * Past CVEs: CVE-2020-0853, CVE-2020-17008
 */

#include <windows.h>
#include <wincodec.h>
#include <stdint.h>
#include <stddef.h>

#pragma comment(lib, "windowscodecs.lib")
#pragma comment(lib, "ole32.lib")

static IWICImagingFactory* g_pIWICFactory = NULL;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    CoInitialize(NULL);

    // Create WIC factory
    CoCreateInstance(
        CLSID_WICImagingFactory,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_PPV_ARGS(&g_pIWICFactory)
    );

    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!g_pIWICFactory || Size < 10 || Size > 10000000) {
        return 0;
    }

    IWICStream* pStream = NULL;
    IWICBitmapDecoder* pDecoder = NULL;

    // Create stream from memory
    if (SUCCEEDED(g_pIWICFactory->CreateStream(&pStream))) {
        if (SUCCEEDED(pStream->InitializeFromMemory((BYTE*)Data, (DWORD)Size))) {

            // Create decoder from stream
            HRESULT hr = g_pIWICFactory->CreateDecoderFromStream(
                pStream,
                NULL,
                WICDecodeMetadataCacheOnDemand,
                &pDecoder
            );

            if (SUCCEEDED(hr) && pDecoder) {
                // Get decoder info
                IWICBitmapDecoderInfo* pDecoderInfo = NULL;
                if (SUCCEEDED(pDecoder->GetDecoderInfo(&pDecoderInfo))) {
                    // Get container format
                    GUID containerFormat;
                    pDecoderInfo->GetContainerFormat(&containerFormat);

                    pDecoderInfo->Release();
                }

                // Get frame count
                UINT frameCount = 0;
                pDecoder->GetFrameCount(&frameCount);

                if (frameCount > 0 && frameCount < 100) {
                    for (UINT i = 0; i < frameCount && i < 10; i++) {
                        IWICBitmapFrameDecode* pFrame = NULL;

                        if (SUCCEEDED(pDecoder->GetFrame(i, &pFrame))) {
                            // Get frame size
                            UINT width, height;
                            pFrame->GetSize(&width, &height);

                            // Prevent excessive memory allocation
                            if (width < 10000 && height < 10000) {
                                // Get pixel format
                                WICPixelFormatGUID pixelFormat;
                                pFrame->GetPixelFormat(&pixelFormat);

                                // Get resolution
                                double dpiX, dpiY;
                                pFrame->GetResolution(&dpiX, &dpiY);

                                // Test metadata reading
                                IWICMetadataQueryReader* pMetadataReader = NULL;
                                if (SUCCEEDED(pFrame->GetMetadataQueryReader(&pMetadataReader))) {
                                    // Try to read some common metadata
                                    PROPVARIANT value;
                                    PropVariantInit(&value);

                                    // EXIF metadata
                                    pMetadataReader->GetMetadataByName(L"/app1/ifd/{ushort=274}", &value);
                                    PropVariantClear(&value);

                                    // XMP metadata
                                    pMetadataReader->GetMetadataByName(L"/xmp", &value);
                                    PropVariantClear(&value);

                                    pMetadataReader->Release();
                                }

                                // Test creating a format converter
                                IWICFormatConverter* pConverter = NULL;
                                if (SUCCEEDED(g_pIWICFactory->CreateFormatConverter(&pConverter))) {
                                    // Convert to 32bpp BGRA
                                    pConverter->Initialize(
                                        pFrame,
                                        GUID_WICPixelFormat32bppBGRA,
                                        WICBitmapDitherTypeNone,
                                        NULL,
                                        0.0,
                                        WICBitmapPaletteTypeCustom
                                    );

                                    // Test thumbnail creation
                                    IWICBitmapScaler* pScaler = NULL;
                                    if (SUCCEEDED(g_pIWICFactory->CreateBitmapScaler(&pScaler))) {
                                        UINT thumbWidth = (width > 100) ? 100 : width;
                                        UINT thumbHeight = (height > 100) ? 100 : height;

                                        pScaler->Initialize(
                                            pConverter,
                                            thumbWidth,
                                            thumbHeight,
                                            WICBitmapInterpolationModeFant
                                        );

                                        pScaler->Release();
                                    }

                                    pConverter->Release();
                                }

                                // Test color context
                                IWICColorContext* pColorContext = NULL;
                                if (SUCCEEDED(g_pIWICFactory->CreateColorContext(&pColorContext))) {
                                    UINT colorContextCount = 0;
                                    pFrame->GetColorContexts(0, NULL, &colorContextCount);

                                    if (colorContextCount > 0 && colorContextCount < 10) {
                                        IWICColorContext** ppColorContexts = new IWICColorContext*[colorContextCount];
                                        pFrame->GetColorContexts(colorContextCount, ppColorContexts, &colorContextCount);

                                        for (UINT j = 0; j < colorContextCount; j++) {
                                            if (ppColorContexts[j]) {
                                                ppColorContexts[j]->Release();
                                            }
                                        }
                                        delete[] ppColorContexts;
                                    }

                                    pColorContext->Release();
                                }
                            }

                            pFrame->Release();
                        }
                    }
                }

                // Test preview image
                IWICBitmapSource* pPreview = NULL;
                if (SUCCEEDED(pDecoder->GetPreview(&pPreview))) {
                    pPreview->Release();
                }

                // Test thumbnail
                IWICBitmapSource* pThumbnail = NULL;
                if (SUCCEEDED(pDecoder->GetThumbnail(&pThumbnail))) {
                    pThumbnail->Release();
                }

                pDecoder->Release();
            }
        }

        pStream->Release();
    }

    return 0;
}
