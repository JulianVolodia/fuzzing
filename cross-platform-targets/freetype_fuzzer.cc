/*
 * FreeType Font Fuzzer (Cross-Platform)
 *
 * FreeType is used in Chrome, Android, Linux, and many other systems
 * for font rendering. It's a critical component with a history of
 * exploited vulnerabilities.
 *
 * Target areas:
 * - TrueType/OpenType parsing
 * - Font hinting
 * - Glyph rasterization
 * - Font table validation
 *
 * Past CVEs: CVE-2020-15999 (actively exploited), CVE-2014-9657, CVE-2018-6942
 *
 * Build:
 *   clang++ -g -O1 -fsanitize=fuzzer,address \
 *     libfreetype_fuzzer.cc \
 *     -I/usr/include/freetype2 -lfreetype \
 *     -o freetype_fuzzer
 */

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_GLYPH_H
#include FT_OUTLINE_H
#include FT_BBOX_H

#include <stdint.h>
#include <stddef.h>

static FT_Library library = NULL;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    FT_Init_FreeType(&library);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (!library || Size < 100) {
        return 0;
    }

    FT_Face face;

    // Try to load font from memory
    FT_Error error = FT_New_Memory_Face(
        library,
        (const FT_Byte*)Data,
        (FT_Long)Size,
        0,  // face_index
        &face
    );

    if (error) {
        return 0;  // Not a valid font
    }

    // Get face properties
    FT_Long num_faces = face->num_faces;
    FT_Long face_index = face->face_index;
    FT_Long num_glyphs = face->num_glyphs;

    // Prevent excessive operations
    if (num_glyphs > 100000) {
        FT_Done_Face(face);
        return 0;
    }

    // Try different face indices if this is a font collection
    if (num_faces > 1 && num_faces < 10) {
        for (FT_Long i = 1; i < num_faces; i++) {
            FT_Face temp_face;
            if (FT_New_Memory_Face(library, (const FT_Byte*)Data, (FT_Long)Size, i, &temp_face) == 0) {
                FT_Done_Face(temp_face);
            }
        }
    }

    // Set character size
    error = FT_Set_Char_Size(
        face,
        0,      // char_width in 1/64th of points
        16*64,  // char_height in 1/64th of points
        300,    // horizontal device resolution
        300     // vertical device resolution
    );

    if (error == 0) {
        // Try to load some glyphs
        for (FT_ULong charcode = 32; charcode < 127 && charcode < (FT_ULong)num_glyphs; charcode++) {
            FT_UInt glyph_index = FT_Get_Char_Index(face, charcode);

            if (glyph_index) {
                // Load glyph
                error = FT_Load_Glyph(face, glyph_index, FT_LOAD_DEFAULT);

                if (error == 0) {
                    // Render glyph
                    error = FT_Render_Glyph(face->glyph, FT_RENDER_MODE_NORMAL);

                    if (error == 0) {
                        // Get glyph metrics
                        FT_Glyph_Metrics metrics = face->glyph->metrics;

                        // Get bitmap (if rendered)
                        FT_Bitmap bitmap = face->glyph->bitmap;

                        // Try to get outline
                        if (face->glyph->format == FT_GLYPH_FORMAT_OUTLINE) {
                            FT_BBox bbox;
                            FT_Outline_Get_BBox(&face->glyph->outline, &bbox);
                        }

                        // Try to get glyph as a standalone object
                        FT_Glyph glyph;
                        if (FT_Get_Glyph(face->glyph, &glyph) == 0) {
                            FT_Done_Glyph(glyph);
                        }
                    }
                }
            }
        }

        // Test kerning if available
        if (FT_HAS_KERNING(face)) {
            FT_UInt left_glyph = FT_Get_Char_Index(face, 'A');
            FT_UInt right_glyph = FT_Get_Char_Index(face, 'V');

            if (left_glyph && right_glyph) {
                FT_Vector kerning;
                FT_Get_Kerning(face, left_glyph, right_glyph, FT_KERNING_DEFAULT, &kerning);
            }
        }

        // Test font variations if available (variable fonts)
        FT_MM_Var* master = NULL;
        if (FT_Get_MM_Var(face, &master) == 0 && master) {
            // Test some variation settings
            if (master->num_axis > 0 && master->num_axis < 10) {
                FT_Fixed coords[10];
                for (unsigned int i = 0; i < master->num_axis; i++) {
                    coords[i] = master->axis[i].def;
                }
                FT_Set_Var_Design_Coordinates(face, master->num_axis, coords);
            }
            FT_Done_MM_Var(library, master);
        }
    }

    // Test getting font information
    FT_String* family_name = face->family_name;
    FT_String* style_name = face->style_name;
    FT_Long face_flags = face->face_flags;
    FT_Long style_flags = face->style_flags;

    // Test getting postscript name
    const char* ps_name = FT_Get_Postscript_Name(face);

    // Test getting sfnt tables (TrueType/OpenType specific)
    FT_ULong length = 0;
    FT_Load_Sfnt_Table(face, FT_MAKE_TAG('h','e','a','d'), 0, NULL, &length);

    FT_Done_Face(face);

    return 0;
}
