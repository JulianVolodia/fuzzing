/*
 * WebP Image Fuzzer (Cross-Platform)
 *
 * WebP is Google's modern image format with lossy and lossless compression.
 * It's natively supported in Chrome and widely used on the web.
 *
 * Target areas:
 * - VP8/VP8L decoding
 * - Lossy and lossless formats
 * - Alpha channel handling
 * - Animation (WebP animated)
 * - Metadata (EXIF, XMP, ICCP)
 *
 * Past CVEs: CVE-2023-4863 (critical RCE, 0-day), CVE-2020-6831, CVE-2018-25011
 *
 * Build:
 *   clang++ -g -O1 -fsanitize=fuzzer,address \
 *     webp_fuzzer.cc \
 *     -lwebp -lwebpdemux \
 *     -o webp_fuzzer
 */

#include <webp/decode.h>
#include <webp/encode.h>
#include <webp/demux.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 12) {
        return 0;
    }

    // Get image features/info
    WebPBitstreamFeatures features;
    VP8StatusCode status = WebPGetFeatures(Data, Size, &features);

    if (status != VP8_STATUS_OK) {
        return 0;  // Not a valid WebP
    }

    // Prevent excessive memory allocation
    if (features.width > 10000 || features.height > 10000) {
        return 0;
    }

    // Decode into RGBA
    int width, height;
    uint8_t* rgba = WebPDecodeRGBA(Data, Size, &width, &height);

    if (rgba) {
        free(rgba);
    }

    // Decode into BGRA
    uint8_t* bgra = WebPDecodeBGRA(Data, Size, &width, &height);

    if (bgra) {
        free(bgra);
    }

    // Try incremental decoding
    WebPDecoderConfig config;
    if (WebPInitDecoderConfig(&config)) {
        config.output.colorspace = MODE_RGBA;

        WebPIDecoder* idec = WebPIDecode(NULL, 0, &config);

        if (idec) {
            // Feed data incrementally
            size_t chunk_size = Size / 4;
            for (size_t offset = 0; offset < Size; offset += chunk_size) {
                size_t remaining = Size - offset;
                size_t current_chunk = (remaining < chunk_size) ? remaining : chunk_size;

                VP8StatusCode status = WebPIAppend(idec, Data + offset, current_chunk);

                if (status == VP8_STATUS_OK || status == VP8_STATUS_SUSPENDED) {
                    int last_y, width, height, stride;
                    uint8_t* output = WebPIDecGetRGB(idec, &last_y, &width, &height, &stride);
                }
            }

            WebPIDelete(idec);
        }

        WebPFreeDecBuffer(&config.output);
    }

    // Test demuxer (for animated WebP and metadata)
    WebPData webp_data;
    webp_data.bytes = Data;
    webp_data.size = Size;

    WebPDemuxer* demux = WebPDemux(&webp_data);

    if (demux) {
        // Get canvas size
        uint32_t canvas_width = WebPDemuxGetI(demux, WEBP_FF_CANVAS_WIDTH);
        uint32_t canvas_height = WebPDemuxGetI(demux, WEBP_FF_CANVAS_HEIGHT);

        // Get frame count
        uint32_t frame_count = WebPDemuxGetI(demux, WEBP_FF_FRAME_COUNT);

        // Get format flags
        uint32_t flags = WebPDemuxGetI(demux, WEBP_FF_FORMAT_FLAGS);

        // Iterate through frames (if animated)
        if (frame_count > 1 && frame_count < 100) {
            WebPIterator iter;
            if (WebPDemuxGetFrame(demux, 1, &iter)) {
                do {
                    // Get frame data
                    WebPData frame_data = iter.fragment;

                    // Decode frame
                    uint8_t* frame_rgba = WebPDecodeRGBA(
                        frame_data.bytes,
                        frame_data.size,
                        &width,
                        &height
                    );

                    if (frame_rgba) {
                        free(frame_rgba);
                    }

                } while (WebPDemuxNextFrame(&iter) && iter.frame_num < 10);

                WebPDemuxReleaseIterator(&iter);
            }
        }

        // Check for EXIF metadata
        WebPChunkIterator chunk_iter;
        if (WebPDemuxGetChunk(demux, "EXIF", 1, &chunk_iter)) {
            // EXIF data is in chunk_iter.chunk
            WebPDemuxReleaseChunkIterator(&chunk_iter);
        }

        // Check for XMP metadata
        if (WebPDemuxGetChunk(demux, "XMP ", 1, &chunk_iter)) {
            // XMP data is in chunk_iter.chunk
            WebPDemuxReleaseChunkIterator(&chunk_iter);
        }

        // Check for ICCP (color profile)
        if (WebPDemuxGetChunk(demux, "ICCP", 1, &chunk_iter)) {
            // ICC profile data is in chunk_iter.chunk
            WebPDemuxReleaseChunkIterator(&chunk_iter);
        }

        WebPDemuxDelete(demux);
    }

    return 0;
}
