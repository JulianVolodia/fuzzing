/*
 * libpng Fuzzer (Cross-Platform)
 *
 * libpng is the reference PNG image format library, used in Chrome,
 * Firefox, and countless applications across all platforms.
 *
 * Target areas:
 * - PNG chunk parsing
 * - Decompression (zlib integration)
 * - Interlacing
 * - Color transformations
 *
 * Past CVEs: CVE-2019-7317, CVE-2018-14550, CVE-2015-8540
 *
 * Build:
 *   clang++ -g -O1 -fsanitize=fuzzer,address libpng_fuzzer.cc -lpng -o libpng_fuzzer
 */

#include <png.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Memory read structure for png_set_read_fn
struct memory_read_state {
    const uint8_t* data;
    size_t size;
    size_t position;
};

static void user_read_data(png_structp png_ptr, png_bytep data, png_size_t length) {
    memory_read_state* state = (memory_read_state*)png_get_io_ptr(png_ptr);

    if (state->position + length > state->size) {
        png_error(png_ptr, "Read error");
        return;
    }

    memcpy(data, state->data + state->position, length);
    state->position += length;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 8) {
        return 0;
    }

    // Check PNG signature
    if (png_sig_cmp((png_bytep)Data, 0, 8) != 0) {
        return 0;  // Not a PNG
    }

    png_structp png_ptr = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png_ptr) {
        return 0;
    }

    png_infop info_ptr = png_create_info_struct(png_ptr);
    if (!info_ptr) {
        png_destroy_read_struct(&png_ptr, NULL, NULL);
        return 0;
    }

    // Error handling
    if (setjmp(png_jmpbuf(png_ptr))) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }

    // Set up memory reading
    memory_read_state state;
    state.data = Data;
    state.size = Size;
    state.position = 0;

    png_set_read_fn(png_ptr, &state, user_read_data);

    // Read PNG info
    png_read_info(png_ptr, info_ptr);

    png_uint_32 width = png_get_image_width(png_ptr, info_ptr);
    png_uint_32 height = png_get_image_height(png_ptr, info_ptr);
    png_byte color_type = png_get_color_type(png_ptr, info_ptr);
    png_byte bit_depth = png_get_bit_depth(png_ptr, info_ptr);

    // Prevent excessive memory allocation
    if (width > 10000 || height > 10000 || width * height > 10000000) {
        png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
        return 0;
    }

    // Apply transformations
    if (color_type == PNG_COLOR_TYPE_PALETTE) {
        png_set_palette_to_rgb(png_ptr);
    }

    if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8) {
        png_set_expand_gray_1_2_4_to_8(png_ptr);
    }

    if (png_get_valid(png_ptr, info_ptr, PNG_INFO_tRNS)) {
        png_set_tRNS_to_alpha(png_ptr);
    }

    if (bit_depth == 16) {
        png_set_strip_16(png_ptr);
    }

    if (color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_GRAY_ALPHA) {
        png_set_gray_to_rgb(png_ptr);
    }

    png_read_update_info(png_ptr, info_ptr);

    // Allocate memory for image
    size_t rowbytes = png_get_rowbytes(png_ptr, info_ptr);
    png_bytep* row_pointers = (png_bytep*)malloc(sizeof(png_bytep) * height);

    if (row_pointers) {
        for (png_uint_32 y = 0; y < height; y++) {
            row_pointers[y] = (png_bytep)malloc(rowbytes);
            if (!row_pointers[y]) {
                // Allocation failed, cleanup
                for (png_uint_32 i = 0; i < y; i++) {
                    free(row_pointers[i]);
                }
                free(row_pointers);
                png_destroy_read_struct(&png_ptr, &info_ptr, NULL);
                return 0;
            }
        }

        // Read the image
        png_read_image(png_ptr, row_pointers);

        // Read end
        png_read_end(png_ptr, info_ptr);

        // Cleanup
        for (png_uint_32 y = 0; y < height; y++) {
            free(row_pointers[y]);
        }
        free(row_pointers);
    }

    png_destroy_read_struct(&png_ptr, &info_ptr, NULL);

    return 0;
}
