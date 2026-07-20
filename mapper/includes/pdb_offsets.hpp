#pragma once

#include "loader_offsets.hpp"
#include <cstdint>

namespace pdb_offsets {
	bool resolve(loader_offsets::block* offsets);
	uint64_t get_symbol_offset(const wchar_t* module_name, const char* symbol_name);
}
