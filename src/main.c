#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "pe_structs.h"

#define IMPORT_SIZE (100)
#define TEXT_BASE   (0x1000)
#define IMAGE_BASE  (0x400000)

uint32_t imp_exit;
uint32_t imp_scanf;
uint32_t imp_printf;

inline static void write_i32(int8_t *buffer, int32_t value) {
    ((int32_t *) buffer)[0] = value;
}

int32_t padding(int32_t amount, int32_t padding) {
	if (amount % padding == 0) {
		return 0;
	}

	return padding - amount % padding;
}

inline static size_t write_padding(FILE *fp, size_t padding_bytes) {
    size_t bytes_written = 0;
    for (size_t i = 0; i < padding_bytes; ++i) {
        bytes_written += fwrite("\0", sizeof(char), 1, fp);
    }

    return bytes_written;
}

int main(void) {
    size_t bytes_written = 0;
    FILE *fp = fopen("result.exe", "wb");

    int8_t imports[512] = { 0 };
    {
        write_i32(&imports[12], TEXT_BASE + 56); // name rva
        write_i32(&imports[16], TEXT_BASE + 40); // first thunk

        write_i32(&imports[40], TEXT_BASE + 67);
        write_i32(&imports[44], TEXT_BASE + 74);
        write_i32(&imports[48], TEXT_BASE + 82);

        memcpy(&imports[56], "msvcrt.dll\x00",     sizeof("msvcrt.dll\x00"));

        //
        //memset(&imports[67], 0, sizeof("\x00\x00exit\x00"));
        memcpy(&imports[69], "exit", sizeof("exit"));
        //

        memcpy(&imports[74], "\x00\x00scanf\x00",  sizeof("\x00\x00scanf\x00"));
        memcpy(&imports[82], "\x00\x00printf\x00", sizeof("\x00\x00printf\x00"));
        memcpy(&imports[91], "%d\x00",             sizeof("%d\x00"));
        memcpy(&imports[94], "%d\n\x00",           sizeof("%d\n\x00"));

        imp_exit   = IMAGE_BASE + TEXT_BASE + 40;
        imp_scanf  = IMAGE_BASE + TEXT_BASE + 44;
        imp_printf = IMAGE_BASE + TEXT_BASE + 48;

        //s_fmt_addr = IMAGE_BASE + TEXT_BASE + 91;
        //p_fmt_addr = IMAGE_BASE + TEXT_BASE + 94;
    }

    int32_t code_bytes = 0;
    char code[512] = { 0 };

    memcpy(&code[0], &imports[0], sizeof(char) * IMPORT_SIZE);
    code_bytes += sizeof(char) * IMPORT_SIZE;

    {
        // ret
        code[code_bytes++] = 0xc3;
    }

    int32_t entry_point_address = TEXT_BASE + IMPORT_SIZE + (code_bytes - sizeof(char) * IMPORT_SIZE);
    fprintf(stderr, "TEXT_BASE:   %d (%X)\n", TEXT_BASE, TEXT_BASE);
    fprintf(stderr, "IMPORT_SIZE: %d (%X)\n", IMPORT_SIZE, IMPORT_SIZE);
    fprintf(stderr, "entry_point: %d (%X)\n", entry_point_address, entry_point_address);

    { // exit

        // push 0x2a
        // call DWORD PTR ds:imp_exit
        // add ESP, 0x4

        code[code_bytes++] = 0x6a;
        code[code_bytes++] = 69; // exit code

        code[code_bytes++] = 0xff;
        code[code_bytes++] = 0x15;
        code[code_bytes++] = (uint8_t) (imp_exit >> 0);
        code[code_bytes++] = (uint8_t) (imp_exit >> 8);
        code[code_bytes++] = (uint8_t) (imp_exit >> 16);
        code[code_bytes++] = (uint8_t) (imp_exit >> 24);

        code[code_bytes++] = 0x83;
        code[code_bytes++] = 0xc4;
        code[code_bytes++] = 0x04;
    }

    int32_t code_segment_padding = padding(code_bytes, 512);
    int32_t code_segment_length  = code_bytes + code_segment_padding;

    // DOS header
	bytes_written += fwrite("MZ", sizeof(char), 2, fp);
	bytes_written += write_padding(fp, 58); // skip loads of crap
	bytes_written += fwrite("\x40\x00\x00\x00", sizeof(char), 4, fp);

    struct PE_File_Header header = {
        .magic   = "PE\x00\x00",
        .machine = IMAGE_FILE_MACHINE_I386,
        .number_of_sections = 1,
        .size_of_optional_header = sizeof(struct Optional_Header_32),
        .characteristics = IMAGE_FILE_BIT32_MACHINE
            | IMAGE_FILE_EXECUTABLE_IMAGE
            | IMAGE_FILE_DEBUG_STRIPPED
            | IMAGE_FILE_RELOCS_STRIPPED
            | IMAGE_FILE_LINE_NUMS_STRIPPED
            | IMAGE_FILE_LOCAL_SYMS_STRIPPED,
	};
    //memset(&header, 0xFF, sizeof(struct PE_File_Header));

	bytes_written += fwrite(&header, sizeof(char), sizeof(struct PE_File_Header), fp);

    struct Optional_Header_32 optional_header = {
        .magic = OPTIONAL_HEADER_MAGIC_PE32,

        .size_of_code = code_segment_length,
        .address_of_entry_point = entry_point_address,
        .base_of_code = TEXT_BASE,
        .base_of_data = TEXT_BASE,
        .image_base   = IMAGE_BASE,

        .section_alignment = 4096,
        .file_alignment    = 512,

        .major_subsystem_version = 4,
        .minor_subsystem_version = 0,

        .size_of_image = code_segment_length + padding(code_segment_length, 0x1000) + 0x1000,
        .size_of_headers = 512,

        .subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI,
        .dll_characteristics = IMAGE_DLLCHARACTERISTICS_NX_COMPAT,

        .size_of_stack_reserve = 0x200000,
        .size_of_stack_commit  = 0x001000,
        .size_of_heap_reserve  = 0x100000,
        .size_of_heap_commit   = 0x001000,

        .number_of_rva_and_sizes = 16,
    };

    optional_header.data_directory[1] = (struct Data_Directory) {
        .virtual_address = TEXT_BASE,
        .size            = IMPORT_SIZE, // ?
    };

    fprintf(stderr, "optional header at %zX\n", bytes_written);
	bytes_written += fwrite(&optional_header, sizeof(char), sizeof(struct Optional_Header_32), fp);

    struct Section_Header_32 section_header = {
		.name = ".blaise\x00",
		.virtual_size    = code_segment_length,
		.virtual_address = TEXT_BASE,

		.size_of_raw_data    = code_segment_length,
		.pointer_to_raw_data = 512,

		.characteristics = IMAGE_SCN_ALIGN_16BYTES
            | IMAGE_SCN_MEM_EXECUTE
            | IMAGE_SCN_MEM_READ
            | IMAGE_SCN_MEM_WRITE,
	};

	bytes_written += fwrite(&section_header, sizeof(char), sizeof(struct Section_Header_32), fp);
    size_t section_padding = padding(bytes_written, 512);
    bytes_written += write_padding(fp, section_padding);

    fprintf(stderr, "padded with %zu bytes. code should be at byte %zu (%d)\n", section_padding, bytes_written, code_segment_length);

    bytes_written += fwrite(&code[0], sizeof(char), code_bytes, fp);
    bytes_written += write_padding(fp, code_segment_padding);

    fclose(fp);
    return 0;
}
