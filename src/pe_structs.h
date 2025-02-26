#if !defined(PE_STRUCTS_H_)
#define PE_STRUCTS_H_

#include <stdint.h>
#include "pe_enums.h"

struct PE_File_Header {
    uint8_t  magic[4];
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    enum IMAGE_FILE characteristics;
} __attribute__((packed));

struct Data_Directory {
    uint32_t virtual_address;
    uint32_t size;
} __attribute__((packed));

struct Optional_Header_32 {
    uint16_t magic;
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;

    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;

    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;

    uint16_t major_image_version;
    uint16_t minor_image_version;

    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;

    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    enum IMAGE_SUBSYSTEM          subsystem;
    enum IMAGE_DLLCHARACTERISTIC dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    struct Data_Directory data_directory[16];
} __attribute__((packed));

struct Optional_Header_64 {
    uint16_t magic;
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t check_sum;
    enum IMAGE_SUBSYSTEM subsystem;
    enum IMAGE_DLLCHARACTERISTIC dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    struct Data_Directory data_directory[16];
} __attribute__((packed));

struct Section_Header_32 {
	uint8_t  name[8];
	uint32_t virtual_size;
	uint32_t virtual_address;
	uint32_t size_of_raw_data;
	uint32_t pointer_to_raw_data;
	uint32_t pointer_to_relocations;
	uint32_t pointer_to_line_numbers;
	uint16_t number_of_relocations;
	uint16_t number_of_line_numbers;
	uint32_t characteristics;
} __attribute__((packed));

#endif // PE_STRUCTS_H_
