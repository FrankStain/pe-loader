#pragma once

#include <windows.h>

#include <string>
#include <vector>
#include <list>
#include <map>
#include <iterator>

using namespace std;

typedef __int8  int8_t;
typedef __int16 int16_t;
typedef __int32 int32_t;
typedef __int64 int64_t;

typedef unsigned __int8  uint8_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int64 uint64_t;

#pragma pack( push, 1 )
namespace pe {	
	static const uint16_t	g_dos_magic				= 0x5A4D;		// "MZ"
	static const uint32_t	g_pe_magic				= 0x00004550;	// "PE"
	static const uint16_t	g_opt_exe32				= 0x010B;		// Win32 EXE
	static const uint16_t	g_opt_exe64				= 0x020B;		// Win64 EXE
	static const uint16_t	g_opt_rom				= 0x0107;		// ROM Image
	static const uint32_t	g_data_dir_count		= 16;
	static const uint32_t	g_sect_hdr_name_size	= 8;
		
	enum loader_state_t {
		ls_error	= -1,
		ls_none		= 0,
		ls_ready,
		ls_opened,
		ls_closed,
		ls_loaded,
		ls_unloaded,
	};

	enum data_dir_index_t {
		ide_export	= 0,
		ide_import,
		ide_resource,
		ide_exception,
		ide_seqrity,
		ide_base_reloc,
		ide_debug,
		ide_architecture,
		ide_global_ptr,
		ide_tls,
		ide_load_config,
		ide_bound_import,
		ide_iat,
		ide_delay_import,
		ide_com_descriptor,
	};

	struct dos_hdr_t {
		uint16_t			m_magic;
		uint16_t			m_cblp;
		uint16_t			m_pages_count;
		uint16_t			m_relocations;
		uint16_t			m_cparhdr;
		
		struct alloc_t {
			uint16_t		m_min;
			uint16_t		m_max;
		}					m_alloc;

		struct registers_t {
			uint16_t		m_ss;
			uint16_t		m_sp;
			uint16_t		m_checksum;
			uint16_t		m_ip;
			uint16_t		m_cs;
		}					m_reg;

		uint16_t			m_reloc_offset;
		uint16_t			m_overlay_num;
		uint16_t			m_reserved_01[4];

		struct oem_t {
			uint16_t		m_id;
			uint16_t		m_info;
		}					m_oem;

		uint16_t			m_reserved_02[10];
		uint32_t			m_offset_next;

		inline const bool is_valid() const { return ( g_dos_magic == m_magic ) && m_offset_next; };
	};

	struct data_dir_t {
		uint32_t			m_offset;
		uint32_t			m_size;
	};

	struct nt_header_t {
		uint32_t		m_magic;

		struct file_hdr_t {
			uint16_t		m_machine;
			uint16_t		m_sections_count;
			uint32_t		m_timedate_stamp;
			uint32_t		m_symbols_offset;
			uint32_t		m_symbols_count;
			uint16_t		m_opt_hdr_size;
			uint16_t		m_characteristics;
		}					m_file_hdr;

		struct optional_hdr_t {
			uint16_t		m_magic;

			struct linker_version_t {
				uint8_t		m_major;
				uint8_t		m_minor;
			}				m_linker_version;

			struct sizes_t {
				uint32_t	m_code;
				uint32_t	m_inited_data;
				uint32_t	m_uninited_data;
			}				m_size;

			uint32_t		m_entry_point;
			
			struct bases_t {
				uint32_t	m_code;
				uint32_t	m_data;
				uint32_t	m_image;
			}				m_base;

			struct alignments_t {
				uint32_t	m_section;
				uint32_t	m_file;
			}				m_alignment;

			struct versions_t {
				uint16_t	m_os_major;
				uint16_t	m_os_minor;
				uint16_t	m_img_major;
				uint16_t	m_img_minor;
				uint16_t	m_subsystem_major;
				uint16_t	m_subsystem_minor;
				uint32_t	m_win32;
			}				m_version;

			uint32_t		m_image_size;
			uint32_t		m_headers_size;
			uint32_t		m_checksum;
			uint16_t		m_subsystem;
			uint16_t		m_dll_flags;

			uint32_t		m_stack_reserve_size;
			uint32_t		m_stack_commit_size;
			uint32_t		m_heap_reserve_size;
			uint32_t		m_heap_commit_size;

			uint32_t		m_loader_flags;
			uint32_t		m_rva_count;

			data_dir_t		m_data_directory[ g_data_dir_count ];
		}					m_optional_hdr;

		const bool is_valid() const { return ( g_pe_magic == m_magic ) && ( g_opt_exe32 == m_optional_hdr.m_magic ); };
	};
	
	struct entry_t {
		void*				m_address;
		int32_t				m_ordinal;
		string				m_name;
		string				m_module;
	};

	union sect_hdr_flags_t {
		uint32_t			m_bits;
		struct {
			uint32_t		m_index_scaled		: 1; // [0x00000001]
			uint32_t		m_r00000002			: 1; // [0x00000002]
			uint32_t		m_r00000004			: 1; // [0x00000004]
			uint32_t		m_r00000008			: 1; // [0x00000008]
			uint32_t		m_r00000010			: 1; // [0x00000010]
			uint32_t		m_has_code			: 1; // [0x00000020]
			uint32_t		m_has_init_data		: 1; // [0x00000040]
			uint32_t		m_has_uninit_data	: 1; // [0x00000080]

			uint32_t		m_link_other		: 1; // [0x00000100]
			uint32_t		m_link_info			: 1; // [0x00000200]
			uint32_t		m_type_over			: 1; // [0x00000400]
			uint32_t		m_link_remove		: 1; // [0x00000800]
			uint32_t		m_link_comdat		: 1; // [0x00001000]
			uint32_t		m_r00002000			: 1; // [0x00002000]
			uint32_t		m_reset_spec_exc	: 1; // [0x00004000]
			uint32_t		m_mem_far_data		: 1; // [0x00008000]

			uint32_t		m_mem_sys_heap		: 1; // [0x00010000]
			uint32_t		m_mem_16bit			: 1; // [0x00020000]
			uint32_t		m_mem_locked		: 1; // [0x00040000]
			uint32_t		m_mem_preload		: 1; // [0x00080000]
			uint32_t		m_mem_align_1b		: 1; // [0x00100000]
			uint32_t		m_mem_align_2b		: 1; // [0x00200000]
			uint32_t		m_mem_align_8b		: 1; // [0x00400000]
			uint32_t		m_mem_align_128b	: 1; // [0x00800000]

			uint32_t		m_link_ext_reloc	: 1; // [0x01000000]
			uint32_t		m_mem_discardable	: 1; // [0x02000000]
			uint32_t		m_mem_not_cached	: 1; // [0x04000000]
			uint32_t		m_mem_not_paged		: 1; // [0x08000000]
			uint32_t		m_mem_shared		: 1; // [0x10000000]
			uint32_t		m_mem_execute		: 1; // [0x20000000]
			uint32_t		m_mem_read			: 1; // [0x40000000]
			uint32_t		m_mem_write			: 1; // [0x80000000]
		};

		inline const bool mem_align_4b() const { return m_mem_align_1b && m_mem_align_2b; };
		inline const bool mem_align_16b() const { return m_mem_align_1b && m_mem_align_8b; };
		inline const bool mem_align_32b() const { return m_mem_align_2b && m_mem_align_8b; };
		inline const bool mem_align_64b() const { return m_mem_align_1b && m_mem_align_2b && m_mem_align_8b; };
		inline const bool mem_align_256b() const { return m_mem_align_1b && m_mem_align_128b; };
		inline const bool mem_align_512b() const { return m_mem_align_2b && m_mem_align_128b; };
		inline const bool mem_align_1024b() const { return m_mem_align_1b && m_mem_align_2b && m_mem_align_128b; };
		inline const bool mem_align_2048b() const { return m_mem_align_8b && m_mem_align_128b; };
		inline const bool mem_align_4096b() const { return m_mem_align_1b && m_mem_align_8b && m_mem_align_128b; };
		inline const bool mem_align_8192b() const { return m_mem_align_1b && m_mem_align_2b && m_mem_align_8b && m_mem_align_128b; };
	};

	struct section_header_t {
		uint8_t				m_name[ g_sect_hdr_name_size ];

		union {
			uint32_t		m_phys_address;
			uint32_t		m_virtual_size;
		};

		uint32_t			m_virtual_address;
		uint32_t			m_raw_data_size;
		uint32_t			m_raw_data_offset;
		uint32_t			m_reloc_offset;
		uint32_t			m_linenum_offset;
		uint16_t			m_reloc_count;
		uint16_t			m_linenum_count;
		sect_hdr_flags_t	m_flags;
	};

	struct reloc_desc_t {
		uint32_t			m_offset;
		uint32_t			m_size;
	};

	struct import_desc_t {
		uint32_t			m_first_thunk_orig;
		uint32_t			m_timestamp;
		uint32_t			m_forward_chain;
		uint32_t			m_name_offset;
		uint32_t			m_first_thunk;
	};

	struct export_desc_t {
		uint32_t			m_flags;
		uint32_t			m_timestamp;
		uint16_t			m_major_version;
		uint16_t			m_minor_version;
		uint32_t			m_name_offset;
		uint32_t			m_ordinal_base;
		uint32_t			m_func_count;
		uint32_t			m_names_count;
		uint32_t			m_func_offset;
		uint32_t			m_names_offset;
		uint32_t			m_ordinals_offset;
	};

	struct import_name_desc_t {
		uint16_t			m_hint;
		uint8_t				m_name[1];
	};
	
	static const uint32_t	g_reloc_desc_size = sizeof( reloc_desc_t );

	typedef BOOL (WINAPI *dll_main_t)( HINSTANCE dll_inst, DWORD call_reason, LPVOID tag );
};
#pragma pack( pop )