#pragma once

namespace loader_offsets {
	inline constexpr ULONG magic = 0x4F444650; // "PFDO"
	inline constexpr ULONG version = 1;

	struct eprocess_offsets {
		ULONG pid;
		ULONG flink;
		ULONG image_name;
		ULONG active_threads;
		ULONG directory_table_base;
		ULONG peb;
		ULONG ldr_data;
	};

	struct block {
		ULONG magic;
		ULONG version;
		ULONG size;
		ULONG reserved;
		ULONG64 driver_size;
		ULONG64 nt_user_get_cpd_rva;
		ULONG64 mm_pfn_database_rva;
		ULONG64 mi_get_page_table_pfn_buddy_rva;
		eprocess_offsets eprocess;
	};
}
