#include "pe_loader.h"

namespace pe {
	uint32_t	g_os_page_size = 0;
	
	loader_t::loader_t() : m_state(ls_none), m_inst(NULL), m_image_base(NULL), m_image_size(0), m_file(INVALID_HANDLE_VALUE), m_map(INVALID_HANDLE_VALUE), m_view(NULL) {
		if( !g_os_page_size ){
			SYSTEM_INFO si;

			GetSystemInfo( &si );
			g_os_page_size = si.dwAllocationGranularity;
		};
	};

	loader_t::~loader_t(){
		close();
		m_state = ls_error;
	};

	void* loader_t::proc_address( const string& name ) const {
		if( !( ( ls_ready == m_state ) && m_exports.size() ) ){
			return NULL;
		};

		void* result = NULL;

		for( exports_t::const_iterator fd = m_exports.begin(); ( m_exports.end() != fd ) && !result; fd++ ){
			if( name == fd->m_name ){
				result = fd->m_address;
			};
		};

		return result;
	};

	void* loader_t::proc_address( const int32_t ordinal ) const {
		if( !( ( ls_ready == m_state ) && m_exports.size() ) ){
			return NULL;
		};

		void* result = NULL;

		for( exports_t::const_iterator fd = m_exports.begin(); ( m_exports.end() != fd ) && !result; fd++ ){
			if( ordinal == fd->m_ordinal ){
				result = fd->m_address;
			};
		};

		return result;
	};

	const bool loader_t::open( const string& path, const bool open_and_load ){
		close();

		if( ls_closed != m_state ){
			return false;
		};

		m_state	= ls_none;
		m_path	= path;

		m_file = CreateFile( m_path.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, NULL, NULL );
		if( !m_file || INVALID_HANDLE_VALUE == m_file ){
			m_state = ls_error;
			return false;
		};

		m_map = CreateFileMapping( m_file, NULL, PAGE_READONLY, 0, 0, NULL );
		if( !m_map || INVALID_HANDLE_VALUE == m_map ){
			close();
			m_state = ls_error;
			return false;
		};

		m_view = (uint8_t*)MapViewOfFile( m_map, SECTION_MAP_READ, 0, 0, 0 );
		if( !m_view ){
			close();
			m_state = ls_error;
			return false;
		};

		m_state = ls_opened;
		return ( open_and_load )? load() : true;
	};

	const bool loader_t::load(){
		if( ls_opened != m_state ){
			return false;
		};

		const dos_hdr_t&	dos_hdr		= *(dos_hdr_t*)m_view;
		if( !dos_hdr.is_valid() ){
			close();
			m_state = ls_error;
			return false;
		};

		const nt_header_t&	nt_hdr		= *(nt_header_t*)( m_view + dos_hdr.m_offset_next );
		if( !nt_hdr.is_valid() ){
			close();
			m_state = ls_error;
			return false;
		};

		m_image_size	= nt_hdr.m_optional_hdr.m_image_size;
		m_image_base	= (uint8_t*)VirtualAlloc( NULL, m_image_size, MEM_RESERVE, PAGE_NOACCESS );
		if( !m_image_base ){
			close();
			m_state = ls_error;
			return false;
		};

		m_section_size	= nt_hdr.m_optional_hdr.m_headers_size;
		m_section_base	= (uint8_t*)VirtualAlloc( m_image_base, m_section_size, MEM_COMMIT, PAGE_READWRITE );
		if( !m_section_base ){
			close();
			m_state = ls_error;
			return false;
		};

		memcpy( m_section_base, m_view, m_section_size );
		
		{
			DWORD tmp;
			VirtualProtect( m_section_base, m_section_size, PAGE_READONLY, &tmp );
		};

		if( !alloc_sections() ){
			return false;
		};

		if( !relink_sections() ){
			return false;
		};

		if( !process_imports() ){
			return false;
		};

		if( !protect_sections() ){
			return false;
		};

		m_state = ls_loaded;

		m_inst = (HMODULE&)m_image_base;
		if( nt_hdr.m_optional_hdr.m_entry_point ){
			dll_main_t main_func	= (dll_main_t)( m_image_base + nt_hdr.m_optional_hdr.m_entry_point );
			if( !main_func( m_inst, DLL_PROCESS_ATTACH, NULL ) ){
				close();
				m_state = ls_error;
				return false;
			};
		};

		if( !process_exports() ){
			return false;
		};

		close_view();
		m_state = ls_ready;
		return true;
	};

	const bool loader_t::unload(){
		if( !m_image_base ){
			return true;
		};

		if( ls_ready == m_state ){
			const dos_hdr_t&	dos_hdr		= *(dos_hdr_t*)m_image_base;
			const nt_header_t&	nt_hdr		= *(nt_header_t*)( m_image_base + dos_hdr.m_offset_next );

			if( nt_hdr.m_optional_hdr.m_entry_point ){
				dll_main_t main_func	= (dll_main_t)( m_image_base + nt_hdr.m_optional_hdr.m_entry_point );

				main_func( m_inst, DLL_PROCESS_DETACH, 0 );
			};
		};

		for( imports_t::iterator fd = m_imports.begin(); m_imports.end() != fd; fd++ ){
			FreeLibrary( fd->second.m_handle );
		};

		m_exports.clear();
		m_imports.clear();
		m_sections.clear();

		VirtualFree( m_image_base, 0, MEM_RELEASE );
		m_image_base	= NULL;
		m_image_size	= 0;
		m_section_base	= NULL;
		m_section_size	= 0;
		m_inst			= NULL;

		m_state = ls_unloaded;
		return true;
	};

	const bool loader_t::close(){
		unload();
		close_view();

		m_state = ls_closed;
		return true;
	};

	void loader_t::close_view(){
		if( m_view && m_map && ( INVALID_HANDLE_VALUE != m_map ) ){
			UnmapViewOfFile( m_view );
		};

		if( m_map && ( INVALID_HANDLE_VALUE != m_map ) ){
			CloseHandle( m_map );
		};

		if( m_file && ( INVALID_HANDLE_VALUE != m_file ) ){
			CloseHandle( m_file );
		};

		m_view	= NULL;
		m_map	= INVALID_HANDLE_VALUE;
		m_file	= INVALID_HANDLE_VALUE;
		m_path	= "";
	};

	const bool loader_t::alloc_sections(){
		const dos_hdr_t&	dos_hdr		= *(dos_hdr_t*)m_image_base;
		const nt_header_t&	nt_hdr		= *(nt_header_t*)( m_image_base + dos_hdr.m_offset_next );

		section_header_t* section = (section_header_t*)( (uint8_t*)&nt_hdr.m_optional_hdr + nt_hdr.m_file_hdr.m_opt_hdr_size );
		m_sections.resize( nt_hdr.m_file_hdr.m_sections_count );
		for( int32_t sd = 0; nt_hdr.m_file_hdr.m_sections_count > sd; sd++ ){
			section_desc_t& desc = m_sections[ sd ];

			desc.m_header	= section;
			desc.m_size		= section->m_virtual_size;
			desc.m_base		= (uint8_t*)VirtualAlloc( m_image_base + section->m_virtual_address, desc.m_size, MEM_COMMIT, PAGE_READWRITE );

			if( !desc.m_base ){
				close();
				m_state = ls_error;
				return false;
			};

			memset( desc.m_base, 0, desc.m_size );
			if( section->m_raw_data_offset && section->m_raw_data_size ){
				memcpy( desc.m_base, m_view + section->m_raw_data_offset, min( desc.m_size, section->m_raw_data_size ) );
			};
			
			section++;
		};

		return true;
	};

	const bool loader_t::relink_sections(){		
		const dos_hdr_t&	dos_hdr			= *(dos_hdr_t*)m_image_base;
		const nt_header_t&	nt_hdr			= *(nt_header_t*)( m_image_base + dos_hdr.m_offset_next );

		if( !nt_hdr.m_optional_hdr.m_data_directory[ ide_base_reloc ].m_offset ){
			return true;
		};

		const uint32_t&		reloc_size		= nt_hdr.m_optional_hdr.m_data_directory[ ide_base_reloc ].m_size;
		const int32_t		reloc_offset	= (int32_t)( m_image_base - nt_hdr.m_optional_hdr.m_base.m_image );
		reloc_desc_t*		reloc_desc		= (reloc_desc_t*)( m_image_base + nt_hdr.m_optional_hdr.m_data_directory[ ide_base_reloc ].m_offset );
		const reloc_desc_t*	reloc_base		= reloc_desc;

		while( reloc_size > (uint32_t)( (uint8_t*)reloc_desc - (uint8_t*)reloc_base ) ){
			uint32_t	lnk_count	= ( reloc_desc->m_size - g_reloc_desc_size ) / 2;
			uint16_t*	lnk			= (uint16_t*)( (uint8_t*)reloc_desc + g_reloc_desc_size );
			uint8_t*	lnk_base	= m_image_base + reloc_desc->m_offset;

			while( lnk_count-- ){
				if( 0xF000 & *lnk ){
					*(uint32_t*)( lnk_base + ( 0x0FFF & *lnk ) ) += reloc_offset;
				};

				lnk++;
			};
			
			reloc_desc = (reloc_desc_t*)lnk;
		};

		return true;
	};

	const DWORD loader_t::section_permitions( const sect_hdr_flags_t& sf ){
		DWORD result = 0;

		if( sf.m_mem_execute ){
			if( sf.m_mem_read ){
				result = ( sf.m_mem_write )? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
			}else{
				result = ( sf.m_mem_write )? PAGE_EXECUTE_WRITECOPY : PAGE_EXECUTE;
			};
		}else{
			if( sf.m_mem_read ){
				result = ( sf.m_mem_write )? PAGE_READWRITE : PAGE_READONLY;
			}else{
				result = ( sf.m_mem_write )? PAGE_WRITECOPY : PAGE_NOACCESS;
			};
		};
		
		return result | ( ( sf.m_mem_not_cached )? PAGE_NOCACHE : 0 );
	};

	const bool loader_t::protect_sections(){
		const dos_hdr_t&	dos_hdr	= *(dos_hdr_t*)m_image_base;
		const nt_header_t&	nt_hdr	= *(nt_header_t*)( m_image_base + dos_hdr.m_offset_next );
		DWORD				tmp		= 0;

		for( sections_t::iterator fd = m_sections.begin(); m_sections.end() != fd; fd++ ){
			if( !VirtualProtect( fd->m_base, fd->m_size, section_permitions( fd->m_header->m_flags ), &tmp ) ){
				close();
				m_state = ls_error;
				return false;
			};
		};

		return true;
	};

	const bool loader_t::import_used( const string& name ){
		imports_t::iterator fd = m_imports.find( name );
		return m_imports.end() != fd;
	};

	const bool loader_t::add_import( const string& name, import_desc_t* desc ){
		import_lib_t lib;

		lib.m_desc		= desc;
		lib.m_name		= name;
		lib.m_handle	= LoadLibrary( name.c_str() );

		if( !lib.m_handle ){
			return false;
		};

		m_imports[ name ] = lib;

		return true;
	};

	const bool loader_t::is_import_ordinal( const uint32_t& func_ptr, HMODULE lib_handle ){
		return 0 != ( 0x80000000U & func_ptr );
	};

	const bool loader_t::process_imports(){
		const dos_hdr_t&	dos_hdr	= *(dos_hdr_t*)m_image_base;
		const nt_header_t&	nt_hdr	= *(nt_header_t*)( m_image_base + dos_hdr.m_offset_next );

		if( !nt_hdr.m_optional_hdr.m_data_directory[ ide_import ].m_offset ){
			return true;
		};

		import_desc_t* imp_desc = (import_desc_t*)( m_image_base + nt_hdr.m_optional_hdr.m_data_directory[ ide_import ].m_offset );

		while( imp_desc->m_name_offset ){
			const string lib_name = (char*)( m_image_base + imp_desc->m_name_offset );

			if( !import_used( lib_name ) ){
				if( !add_import( lib_name, imp_desc ) ){
					close();
					m_state = ls_error;
					return false;
				};
			};

			const import_lib_t&	lib = m_imports[ lib_name ];

			for( uint32_t* func_ptr = (uint32_t*)( m_image_base + ( ( imp_desc->m_timestamp )? imp_desc->m_first_thunk_orig : imp_desc->m_first_thunk ) ); *func_ptr; func_ptr++ ){
				if( is_import_ordinal( *func_ptr, lib.m_handle ) ){
					*func_ptr = (uint32_t)GetProcAddress( lib.m_handle, (LPCSTR)( 0xFFFFU & *func_ptr ) );
				}else{
					*func_ptr = (uint32_t)GetProcAddress( lib.m_handle, (LPCSTR)( ((import_name_desc_t*)( m_image_base + *func_ptr ))->m_name ) );
				};

				if( !*func_ptr ){
					close();
					m_state = ls_error;
					return false;
				};
			};

			imp_desc++;
		};

		return true;
	};

	const bool loader_t::process_exports(){
		const dos_hdr_t&	dos_hdr	= *(dos_hdr_t*)m_image_base;
		const nt_header_t&	nt_hdr	= *(nt_header_t*)( m_image_base + dos_hdr.m_offset_next );

		if( !nt_hdr.m_optional_hdr.m_data_directory[ ide_export ].m_offset ){
			return true;
		};

		const uint32_t& section_size	= nt_hdr.m_optional_hdr.m_data_directory[ ide_export ].m_size;
		const export_desc_t& exports	= *(export_desc_t*)( m_image_base + nt_hdr.m_optional_hdr.m_data_directory[ ide_export ].m_offset );
		const uint32_t* const func_ptrs	= (uint32_t*)( m_image_base + exports.m_func_offset );
		const uint32_t* const names		= (uint32_t*)( m_image_base + exports.m_names_offset );
		const uint16_t* const ordinals	= (uint16_t*)( m_image_base + exports.m_ordinals_offset );
		const char* const module_name	= (char*)( m_image_base + exports.m_name_offset );

		for( uint32_t fd = 0; exports.m_names_count > fd; fd++ ){
			entry_t func;

			func.m_module	= module_name;
			func.m_name		= (char*)( m_image_base + names[ fd ] );
			func.m_ordinal	= ordinals[ fd ];
			func.m_address	= m_image_base + func_ptrs[ func.m_ordinal ];

			if( ( func.m_address > &exports ) && ( section_size > ( (uint32_t)func.m_address - (uint32_t)&exports ) ) ){
				func.m_module = func.m_name.substr( 0, func.m_name.find( '.' ) ) + ".dll";
				func.m_name = func.m_name.substr( func.m_module.size() + 1 );

				if( '#' == func.m_name.front() ){
					func.m_name = func.m_name.substr( 1 );
				};

				if( !import_used( func.m_module ) ){
					if( !add_import( func.m_module, NULL ) ){
						close();
						m_state = ls_error;
						return false;
					};
				};

				const import_lib_t&	lib = m_imports[ func.m_module ];

				func.m_address = GetProcAddress( lib.m_handle, func.m_name.c_str() );
				if( !func.m_address ){
					close();
					m_state = ls_error;
					return false;
				};
			};

			m_exports.push_back( func );
		};

		return true;
	};
};
