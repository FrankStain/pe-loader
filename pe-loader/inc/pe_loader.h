#pragma once

#include "pe_common.h"

namespace pe {
	struct section_desc_t {
		section_header_t*	m_header;
		uint8_t*			m_base;
		uint32_t			m_size;
	};

	struct import_lib_t {
		import_desc_t*		m_desc;
		string				m_name;
		HMODULE				m_handle;
	};
	
	class loader_t {
	private:
		typedef vector<section_desc_t>		sections_t;
		typedef vector<entry_t>				exports_t;
		typedef map<string, import_lib_t>	imports_t;
		
		loader_state_t	m_state;
		HMODULE			m_inst;
		uint8_t*		m_image_base;
		size_t			m_image_size;
		uint8_t*		m_section_base;
		size_t			m_section_size;

		HANDLE			m_file;
		HANDLE			m_map;
		uint8_t*		m_view;

		sections_t		m_sections;
		exports_t		m_exports;
		imports_t		m_imports;
		string			m_path;

		const bool alloc_sections();
		const bool relink_sections();
		const bool protect_sections();

		const bool process_imports();
		const bool import_used( const string& name );
		const bool add_import( const string& name, import_desc_t* desc );
		const bool is_import_ordinal( const uint32_t& func_ptr, HMODULE lib_handle );
		const bool process_exports();
		
		const DWORD section_permitions( const sect_hdr_flags_t& sf );

		void close_view();

	public:
		loader_t();
		~loader_t();

		const bool open( const string& path, const bool open_and_load = false );
		const bool load();
		const bool unload();
		const bool close();

		HMODULE handle() const { return m_inst; };
		HINSTANCE instance() const { return (HINSTANCE&)m_inst; };
		loader_state_t state() const { return m_state; };
		void* proc_address( const string& name ) const;
		void* proc_address( const int32_t ordinal ) const;
	};
};
