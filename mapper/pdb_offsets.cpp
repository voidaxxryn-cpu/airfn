#include "includes/pdb_offsets.hpp"

#include <Windows.h>
#include <winhttp.h>
#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <system_error>
#include <vector>
#include <unordered_map>

#include "includes/utils.hpp"

#pragma comment(lib, "winhttp.lib")

namespace {
	constexpr char pdb_magic[] = "Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53";
	constexpr uint32_t pdb_info_stream = 1;
	constexpr uint32_t tpi_stream = 2;
	constexpr uint16_t s_ldata32 = 0x110C;
	constexpr uint16_t s_gdata32 = 0x110D;
	constexpr uint16_t s_pub32 = 0x110E;
	constexpr uint16_t s_lproc32 = 0x110F;
	constexpr uint16_t s_gproc32 = 0x1110;
	constexpr uint16_t lf_fieldlist = 0x1203;
	constexpr uint16_t lf_bclass = 0x1400;
	constexpr uint16_t lf_vbclass = 0x1401;
	constexpr uint16_t lf_ivbclass = 0x1402;
	constexpr uint16_t lf_index = 0x1404;
	constexpr uint16_t lf_vfunctab = 0x1409;
	constexpr uint16_t lf_enumerate = 0x1502;
	constexpr uint16_t lf_member = 0x150D;
	constexpr uint16_t lf_static_member = 0x150E;
	constexpr uint16_t lf_method = 0x150F;
	constexpr uint16_t lf_nesttype = 0x1510;
	constexpr uint16_t lf_onemethod = 0x1511;
	constexpr uint16_t lf_structure = 0x1505;
	constexpr uint16_t lf_class = 0x1504;
	constexpr uint16_t lf_char = 0x8000;
	constexpr uint16_t lf_short = 0x8001;
	constexpr uint16_t lf_ushort = 0x8002;
	constexpr uint16_t lf_long = 0x8003;
	constexpr uint16_t lf_ulong = 0x8004;
	constexpr uint16_t lf_quadword = 0x8009;
	constexpr uint16_t lf_uquadword = 0x800A;

#pragma pack(push, 1)
	struct msf_super_block {
		char magic[32];
		uint32_t block_size;
		uint32_t free_block_map_block;
		uint32_t num_blocks;
		uint32_t num_directory_bytes;
		uint32_t unknown;
		uint32_t block_map_addr;
	};

	struct tpi_header {
		uint32_t version;
		uint32_t header_size;
		uint32_t type_index_begin;
		uint32_t type_index_end;
		uint32_t type_record_bytes;
		uint16_t hash_stream_index;
		uint16_t hash_aux_stream_index;
		uint32_t hash_key_size;
		uint32_t num_hash_buckets;
		int32_t hash_value_buffer_offset;
		uint32_t hash_value_buffer_length;
		int32_t index_offset_buffer_offset;
		uint32_t index_offset_buffer_length;
		int32_t hash_adj_buffer_offset;
		uint32_t hash_adj_buffer_length;
	};

	struct cv_info_pdb70 {
		uint32_t signature;
		GUID guid;
		uint32_t age;
		char pdb_file_name[1];
	};

	struct dbi_header {
		int32_t signature;
		uint32_t version_header;
		uint32_t age;
		uint16_t global_stream_index;
		uint16_t build_number;
		uint16_t public_stream_index;
		uint16_t pdb_dll_version;
		uint16_t sym_record_stream;
		uint16_t pdb_dll_rbld;
		int32_t mod_info_size;
		int32_t section_contribution_size;
		int32_t section_map_size;
		int32_t source_info_size;
		int32_t type_server_size;
		uint32_t mfc_type_server_index;
		int32_t optional_dbg_header_size;
		int32_t ec_substream_size;
		uint16_t flags;
		uint16_t machine;
		uint32_t padding;
	};

	struct pubsym32 {
		uint16_t record_len;
		uint16_t record_type;
		uint32_t flags;
		uint32_t offset;
		uint16_t segment;
		char name[1];
	};

	struct datasym32 {
		uint16_t record_len;
		uint16_t record_type;
		uint32_t type_index;
		uint32_t offset;
		uint16_t segment;
		char name[1];
	};

	struct procsym32_prefix {
		uint16_t record_len;
		uint16_t record_type;
		uint32_t parent;
		uint32_t end;
		uint32_t next;
		uint32_t length;
		uint32_t debug_start;
		uint32_t debug_end;
		uint32_t type_index;
		uint32_t offset;
		uint16_t segment;
		uint8_t flags;
		char name[1];
	};

	struct section_contribution {
		uint16_t section;
		char padding1[2];
		int32_t offset;
		int32_t size;
		uint32_t characteristics;
		uint16_t module_index;
		char padding2[2];
		uint32_t data_crc;
		uint32_t reloc_crc;
	};

	struct dbi_module_info {
		uint32_t opened;
		section_contribution contribution;
		uint16_t flags;
		uint16_t module_symbol_stream;
		uint32_t symbol_bytes;
		uint32_t c11_bytes;
		uint32_t c13_bytes;
		uint16_t source_file_count;
		char padding[2];
		uint32_t unused;
		uint32_t source_file_name_index;
		uint32_t pdb_file_path_name_index;
		char module_name[1];
	};
#pragma pack(pop)

	struct stream_data {
		uint32_t size = 0;
		std::vector<uint8_t> data;
	};

	struct member_data {
		std::string name;
		uint64_t offset = 0;
	};

	struct type_data {
		uint32_t index = 0;
		uint16_t kind = 0;
		uint32_t field_list = 0;
		uint16_t properties = 0;
		std::string name;
		std::vector<member_data> members;
	};

	struct public_symbol {
		std::string name;
		uint32_t offset = 0;
		uint16_t segment = 0;
	};

	struct pdb_context {
		std::vector<uint8_t> raw;
		std::vector<stream_data> streams;
		uint32_t type_index_begin = 0;
		std::vector<type_data> types;
		std::vector<public_symbol> public_symbols;
	};

	bool http_download(const std::wstring& url, const std::filesystem::path& dest) {
		URL_COMPONENTS uc = {};
		uc.dwStructSize = sizeof(uc);
		wchar_t host[256] = {}, path[2048] = {};
		uc.lpszHostName = host;
		uc.dwHostNameLength = _countof(host);
		uc.lpszUrlPath = path;
		uc.dwUrlPathLength = _countof(path);
		if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc))
			return false;

		HINTERNET session = WinHttpOpen(L"Microsoft-Symbol-Server/10.0",
			WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, nullptr, nullptr, 0);
		if (!session) return false;

		HINTERNET connect = WinHttpConnect(session, host, uc.nPort, 0);
		if (!connect) { WinHttpCloseHandle(session); return false; }

		const DWORD flags = (uc.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
		HINTERNET request = WinHttpOpenRequest(connect, L"GET", path, nullptr,
			WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
		if (!request) {
			WinHttpCloseHandle(connect);
			WinHttpCloseHandle(session);
			return false;
		}

		bool ok = WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
			WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
			WinHttpReceiveResponse(request, nullptr);

		if (ok) {
			DWORD status = 0, status_size = sizeof(status);
			ok = WinHttpQueryHeaders(request,
				WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
				nullptr, &status, &status_size, nullptr) && status == 200;
		}

		if (ok) {
			std::ofstream out(dest, std::ios::binary);
			ok = !!out;
			char buf[65536];
			DWORD n;
			while (ok && WinHttpReadData(request, buf, sizeof(buf), &n) && n > 0)
				ok = !!out.write(buf, n);
			ok = ok && out.good();
		}

		WinHttpCloseHandle(request);
		WinHttpCloseHandle(connect);
		WinHttpCloseHandle(session);
		return ok;
	}

	std::wstring get_system_module_path(const wchar_t* module_name) {
		wchar_t system_dir[MAX_PATH] = { 0 };
		if (!GetSystemDirectoryW(system_dir, MAX_PATH))
			return {};

		std::filesystem::path path(system_dir);
		path /= module_name;
		return path.wstring();
	}

	bool read_file(const std::wstring& path, std::vector<uint8_t>* data) {
		std::ifstream file(path, std::ios::binary);
		if (!file)
			return false;

		file.seekg(0, std::ios::end);
		const std::streamoff size = file.tellg();
		if (size <= 0)
			return false;

		file.seekg(0, std::ios::beg);
		data->resize(static_cast<size_t>(size));
		return !!file.read(reinterpret_cast<char*>(data->data()), size);
	}

	bool has_pdb_msf_magic(const std::filesystem::path& path) {
		std::ifstream file(path, std::ios::binary);
		if (!file)
			return false;

		char magic[sizeof(pdb_magic) - 1] = { 0 };
		return !!file.read(magic, sizeof(magic)) &&
			memcmp(magic, pdb_magic, sizeof(magic)) == 0;
	}

	void* rva_to_ptr(std::vector<uint8_t>& image, DWORD rva) {
		if (image.size() < sizeof(IMAGE_DOS_HEADER))
			return nullptr;

		auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
			return nullptr;

		auto section = IMAGE_FIRST_SECTION(nt);
		for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
			const DWORD section_start = section[i].VirtualAddress;
			const DWORD section_size = (std::max)(section[i].Misc.VirtualSize, section[i].SizeOfRawData);
			if (rva >= section_start && rva < section_start + section_size) {
				const DWORD raw = section[i].PointerToRawData + (rva - section_start);
				if (raw < image.size())
					return image.data() + raw;
			}
		}

		return nullptr;
	}

	std::wstring widen_ascii(const char* value) {
		std::wstring out;
		while (*value)
			out.push_back(static_cast<unsigned char>(*value++));
		return out;
	}

	std::wstring pdb_guid_age(const GUID& guid, uint32_t age) {
		std::wstringstream ss;
		ss << std::uppercase << std::hex << std::setfill(L'0')
			<< std::setw(8) << guid.Data1
			<< std::setw(4) << guid.Data2
			<< std::setw(4) << guid.Data3;

		for (unsigned char byte : guid.Data4)
			ss << std::setw(2) << static_cast<unsigned int>(byte);

		ss << std::hex << age;
		return ss.str();
	}

	bool find_module_pdb(const wchar_t* module_name, std::wstring* pdb_path) {
		const std::wstring module_path = get_system_module_path(module_name);
		if (module_path.empty())
			return false;

		std::vector<uint8_t> image;
		if (!read_file(module_path, &image)) {
			Log(L"[-] Failed to read " << module_path << std::endl);
			return false;
		}

		auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
		auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
		const auto& debug_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
		auto debug = reinterpret_cast<IMAGE_DEBUG_DIRECTORY*>(rva_to_ptr(image, debug_dir.VirtualAddress));
		if (!debug) {
			Log(L"[-] " << module_name << L" debug directory not found" << std::endl);
			return false;
		}

		const uint32_t debug_count = debug_dir.Size / sizeof(IMAGE_DEBUG_DIRECTORY);
		for (uint32_t i = 0; i < debug_count; ++i) {
			if (debug[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW)
				continue;

			if (debug[i].PointerToRawData + sizeof(cv_info_pdb70) > image.size())
				continue;

			auto cv = reinterpret_cast<cv_info_pdb70*>(image.data() + debug[i].PointerToRawData);
			if (cv->signature != 'SDSR')
				continue;

			const std::filesystem::path pdb_file = std::filesystem::path(cv->pdb_file_name).filename();
			const std::wstring pdb_name = widen_ascii(pdb_file.string().c_str());
			const std::wstring guid_age = pdb_guid_age(cv->guid, cv->age);

			wchar_t temp_path[MAX_PATH] = { 0 };
			GetTempPathW(MAX_PATH, temp_path);
			std::filesystem::path cache_path(temp_path);
			cache_path /= L"physmem_symbols";
			cache_path /= pdb_name;
			cache_path /= guid_age;
			std::filesystem::create_directories(cache_path);

			std::filesystem::path local_path = cache_path / pdb_name;
			if (std::filesystem::exists(local_path)) {
				if (has_pdb_msf_magic(local_path)) {
					*pdb_path = local_path.wstring();
					Log(L"[+] Using cached PDB " << *pdb_path << std::endl);
					return true;
				}

				Log(L"[~] Cached PDB is invalid, redownloading " << local_path.wstring() << std::endl);
				std::error_code ec;
				std::filesystem::remove(local_path, ec);
			}

			const std::wstring url = L"https://msdl.microsoft.com/download/symbols/" + pdb_name + L"/" + guid_age + L"/" + pdb_name;
			Log(L"[+] Downloading PDB " << url << std::endl);
			if (!http_download(url, local_path)) {
				Log(L"[-] Failed to download PDB from " << url << std::endl);
				std::error_code ec;
				std::filesystem::remove(local_path, ec);
				return false;
			}

			if (!has_pdb_msf_magic(local_path)) {
				Log(L"[-] Downloaded PDB has invalid MSF magic: " << local_path.wstring() << std::endl);
				std::error_code ec;
				std::filesystem::remove(local_path, ec);
				return false;
			}

			*pdb_path = local_path.wstring();
			return true;
		}

		Log(L"[-] CodeView RSDS record not found in " << module_name << std::endl);
		return false;
	}

	bool get_section_rva(const wchar_t* module_name, uint16_t segment, uint32_t* section_rva) {
		if (!segment)
			return false;

		const std::wstring module_path = get_system_module_path(module_name);
		std::vector<uint8_t> image;
		if (!read_file(module_path, &image))
			return false;

		auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
		if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			return false;

		auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
		if (nt->Signature != IMAGE_NT_SIGNATURE)
			return false;

		if (segment > nt->FileHeader.NumberOfSections)
			return false;

		auto section = IMAGE_FIRST_SECTION(nt);
		*section_rva = section[segment - 1].VirtualAddress;
		return true;
	}

	bool parse_streams(pdb_context* ctx) {
		if (ctx->raw.size() < sizeof(msf_super_block))
			return false;

		auto sb = reinterpret_cast<const msf_super_block*>(ctx->raw.data());
		if (memcmp(sb->magic, pdb_magic, sizeof(pdb_magic) - 1) != 0) {
			Log(L"[-] Invalid PDB MSF magic" << std::endl);
			return false;
		}

		const uint32_t block_size = sb->block_size;
		const uint32_t dir_blocks = (sb->num_directory_bytes + block_size - 1) / block_size;
		const uint64_t block_map_offset = static_cast<uint64_t>(sb->block_map_addr) * block_size;
		if (block_map_offset + static_cast<uint64_t>(dir_blocks) * sizeof(uint32_t) > ctx->raw.size())
			return false;

		auto block_map = reinterpret_cast<const uint32_t*>(ctx->raw.data() + block_map_offset);
		std::vector<uint8_t> directory(static_cast<size_t>(dir_blocks) * block_size);
		for (uint32_t i = 0; i < dir_blocks; ++i) {
			const uint64_t source = static_cast<uint64_t>(block_map[i]) * block_size;
			if (source + block_size > ctx->raw.size())
				return false;
			memcpy(directory.data() + static_cast<size_t>(i) * block_size, ctx->raw.data() + source, block_size);
		}

		const uint32_t* cursor = reinterpret_cast<const uint32_t*>(directory.data());
		const uint32_t stream_count = *cursor++;
		ctx->streams.resize(stream_count);

		for (uint32_t i = 0; i < stream_count; ++i)
			ctx->streams[i].size = *cursor++;

		for (uint32_t i = 0; i < stream_count; ++i) {
			if (ctx->streams[i].size == 0 || ctx->streams[i].size == 0xFFFFFFFF)
				continue;

			const uint32_t blocks = (ctx->streams[i].size + block_size - 1) / block_size;
			ctx->streams[i].data.resize(static_cast<size_t>(blocks) * block_size);
			for (uint32_t b = 0; b < blocks; ++b) {
				const uint32_t block_id = *cursor++;
				const uint64_t source = static_cast<uint64_t>(block_id) * block_size;
				if (source + block_size > ctx->raw.size())
					return false;
				memcpy(ctx->streams[i].data.data() + static_cast<size_t>(b) * block_size, ctx->raw.data() + source, block_size);
			}
		}

		return true;
	}

	void add_symbol(pdb_context* ctx, const char* name, size_t max_name_len, uint32_t offset, uint16_t segment) {
		const size_t name_len = strnlen(name, max_name_len);
		ctx->public_symbols.push_back({
			std::string(name, name_len),
			offset,
			segment
			});
	}

	void parse_symbol_records(pdb_context* ctx, const uint8_t* ptr, const uint8_t* end) {
		while (ptr + sizeof(uint16_t) * 2 <= end) {
			const uint16_t record_len = *reinterpret_cast<const uint16_t*>(ptr);
			if (!record_len || ptr + sizeof(uint16_t) + record_len > end)
				break;

			const uint16_t record_type = *reinterpret_cast<const uint16_t*>(ptr + sizeof(uint16_t));
			if (record_type == s_pub32 && record_len >= sizeof(pubsym32) - sizeof(uint16_t)) {
				auto pub = reinterpret_cast<const pubsym32*>(ptr);
				const size_t max_name_len = record_len - (offsetof(pubsym32, name) - sizeof(uint16_t));
				add_symbol(ctx, pub->name, max_name_len, pub->offset, pub->segment);
			}
			else if ((record_type == s_gdata32 || record_type == s_ldata32) && record_len >= sizeof(datasym32) - sizeof(uint16_t)) {
				auto data = reinterpret_cast<const datasym32*>(ptr);
				const size_t max_name_len = record_len - (offsetof(datasym32, name) - sizeof(uint16_t));
				add_symbol(ctx, data->name, max_name_len, data->offset, data->segment);
			}
			else if ((record_type == s_gproc32 || record_type == s_lproc32) && record_len >= sizeof(procsym32_prefix) - sizeof(uint16_t)) {
				auto proc = reinterpret_cast<const procsym32_prefix*>(ptr);
				const size_t max_name_len = record_len - (offsetof(procsym32_prefix, name) - sizeof(uint16_t));
				add_symbol(ctx, proc->name, max_name_len, proc->offset, proc->segment);
			}

			ptr += sizeof(uint16_t) + record_len;
		}
	}

	bool parse_module_symbols(pdb_context* ctx, const dbi_header* dbi) {
		const uint8_t* ptr = reinterpret_cast<const uint8_t*>(dbi + 1);
		const uint8_t* end = ptr + dbi->mod_info_size;

		while (ptr + sizeof(dbi_module_info) <= end) {
			auto mod = reinterpret_cast<const dbi_module_info*>(ptr);

			if (mod->module_symbol_stream != 0xFFFF &&
				ctx->streams.size() > mod->module_symbol_stream &&
				ctx->streams[mod->module_symbol_stream].data.size() >= sizeof(uint32_t)) {
				const auto& stream = ctx->streams[mod->module_symbol_stream];
				const uint8_t* sym_ptr = stream.data.data();
				const uint8_t* sym_end = sym_ptr + stream.size;

				const uint32_t signature = *reinterpret_cast<const uint32_t*>(sym_ptr);
				if (signature == 4 || signature == 0xeffe0000) {
					sym_ptr += sizeof(uint32_t);
				}

				parse_symbol_records(ctx, sym_ptr, sym_end);
			}

			const uint8_t* names = reinterpret_cast<const uint8_t*>(mod->module_name);
			const uint8_t* module_name_end = static_cast<const uint8_t*>(memchr(names, 0, end - names));
			if (!module_name_end)
				return false;

			const uint8_t* object_name = module_name_end + 1;
			const uint8_t* object_name_end = static_cast<const uint8_t*>(memchr(object_name, 0, end - object_name));
			if (!object_name_end)
				return false;

			ptr = object_name_end + 1;
			ptr += (4 - (reinterpret_cast<uintptr_t>(ptr) & 3)) & 3;
		}

		return true;
	}

	bool parse_public_symbols(pdb_context* ctx) {
		if (ctx->streams.size() <= 3 || ctx->streams[3].data.size() < sizeof(dbi_header))
			return false;

		auto dbi = reinterpret_cast<const dbi_header*>(ctx->streams[3].data.data());
		if (ctx->streams.size() <= dbi->sym_record_stream)
			return false;

		const auto& stream = ctx->streams[dbi->sym_record_stream];
		parse_symbol_records(ctx, stream.data.data(), stream.data.data() + stream.size);

		return parse_module_symbols(ctx, dbi);
	}

	bool parse_cv_integer(const uint8_t*& ptr, uint32_t& remaining, uint64_t* value) {
		if (remaining < sizeof(uint16_t))
			return false;

		const uint16_t leaf = *reinterpret_cast<const uint16_t*>(ptr);
		ptr += sizeof(uint16_t);
		remaining -= sizeof(uint16_t);

		if (leaf < 0x8000) {
			*value = leaf;
			return true;
		}

		uint32_t bytes = 0;
		switch (leaf) {
		case lf_char: bytes = sizeof(int8_t); break;
		case lf_short: bytes = sizeof(int16_t); break;
		case lf_ushort: bytes = sizeof(uint16_t); break;
		case lf_long: bytes = sizeof(int32_t); break;
		case lf_ulong: bytes = sizeof(uint32_t); break;
		case lf_quadword: bytes = sizeof(int64_t); break;
		case lf_uquadword: bytes = sizeof(uint64_t); break;
		default: return false;
		}

		if (remaining < bytes)
			return false;

		switch (leaf) {
		case lf_char: *value = *reinterpret_cast<const int8_t*>(ptr); break;
		case lf_short: *value = *reinterpret_cast<const int16_t*>(ptr); break;
		case lf_ushort: *value = *reinterpret_cast<const uint16_t*>(ptr); break;
		case lf_long: *value = *reinterpret_cast<const int32_t*>(ptr); break;
		case lf_ulong: *value = *reinterpret_cast<const uint32_t*>(ptr); break;
		case lf_quadword: *value = *reinterpret_cast<const int64_t*>(ptr); break;
		case lf_uquadword: *value = *reinterpret_cast<const uint64_t*>(ptr); break;
		}

		ptr += bytes;
		remaining -= bytes;
		return true;
	}

	bool read_c_string(const uint8_t*& ptr, uint32_t& remaining, std::string* value) {
		const void* zero = memchr(ptr, 0, remaining);
		if (!zero)
			return false;

		const size_t length = static_cast<const uint8_t*>(zero) - ptr;
		value->assign(reinterpret_cast<const char*>(ptr), length);
		ptr += length + 1;
		remaining -= static_cast<uint32_t>(length + 1);
		return true;
	}

	bool skip_c_string(const uint8_t*& ptr, uint32_t& remaining) {
		std::string ignored;
		return read_c_string(ptr, remaining, &ignored);
	}

	void skip_padding(const uint8_t*& ptr, uint32_t& remaining) {
		while (remaining && *ptr >= 0xF0) {
			const uint8_t pad = *ptr & 0x0F;
			const uint32_t amount = std::min<uint32_t>(pad, remaining);
			ptr += amount;
			remaining -= amount;
		}
	}

	type_data* find_type(pdb_context* ctx, uint32_t index) {
		if (index < ctx->type_index_begin)
			return nullptr;

		const uint32_t vector_index = index - ctx->type_index_begin;
		if (vector_index >= ctx->types.size())
			return nullptr;

		return &ctx->types[vector_index];
	}

	bool parse_fieldlist(const uint8_t* data, uint32_t size, type_data* type) {
		const uint8_t* ptr = data;
		uint32_t remaining = size;

		while (remaining >= sizeof(uint16_t)) {
			skip_padding(ptr, remaining);
			if (remaining < sizeof(uint16_t))
				break;

			const uint16_t leaf = *reinterpret_cast<const uint16_t*>(ptr);
			ptr += sizeof(uint16_t);
			remaining -= sizeof(uint16_t);

			if (leaf == lf_member) {
				if (remaining < sizeof(uint16_t) + sizeof(uint32_t))
					return false;

				ptr += sizeof(uint16_t); // attributes
				ptr += sizeof(uint32_t); // type index
				remaining -= sizeof(uint16_t) + sizeof(uint32_t);

				uint64_t offset = 0;
				if (!parse_cv_integer(ptr, remaining, &offset))
					return false;

				std::string name;
				if (!read_c_string(ptr, remaining, &name))
					return false;

				type->members.push_back({ name, offset });
			}
			else if (leaf == lf_enumerate) {
				if (remaining < sizeof(uint16_t))
					return false;

				ptr += sizeof(uint16_t); // attributes
				remaining -= sizeof(uint16_t);

				uint64_t value = 0;
				if (!parse_cv_integer(ptr, remaining, &value) || !skip_c_string(ptr, remaining))
					return false;
			}
			else if (leaf == lf_bclass) {
				if (remaining < sizeof(uint16_t) + sizeof(uint32_t))
					return false;

				ptr += sizeof(uint16_t); // attributes
				ptr += sizeof(uint32_t); // base type
				remaining -= sizeof(uint16_t) + sizeof(uint32_t);

				uint64_t offset = 0;
				if (!parse_cv_integer(ptr, remaining, &offset))
					return false;
			}
			else if (leaf == lf_vbclass || leaf == lf_ivbclass) {
				if (remaining < sizeof(uint16_t) + sizeof(uint32_t) * 2)
					return false;

				ptr += sizeof(uint16_t); // attributes
				ptr += sizeof(uint32_t); // base type
				ptr += sizeof(uint32_t); // vbptr type
				remaining -= sizeof(uint16_t) + sizeof(uint32_t) * 2;

				uint64_t vbptr_offset = 0;
				uint64_t vtable_offset = 0;
				if (!parse_cv_integer(ptr, remaining, &vbptr_offset) ||
					!parse_cv_integer(ptr, remaining, &vtable_offset))
					return false;
			}
			else if (leaf == lf_static_member || leaf == lf_nesttype) {
				if (remaining < sizeof(uint16_t) + sizeof(uint32_t))
					return false;

				ptr += sizeof(uint16_t); // attributes
				ptr += sizeof(uint32_t); // type index
				remaining -= sizeof(uint16_t) + sizeof(uint32_t);

				if (!skip_c_string(ptr, remaining))
					return false;
			}
			else if (leaf == lf_method) {
				if (remaining < sizeof(uint16_t) + sizeof(uint32_t))
					return false;

				ptr += sizeof(uint16_t); // overload count
				ptr += sizeof(uint32_t); // method list
				remaining -= sizeof(uint16_t) + sizeof(uint32_t);

				if (!skip_c_string(ptr, remaining))
					return false;
			}
			else if (leaf == lf_onemethod) {
				if (remaining < sizeof(uint16_t) + sizeof(uint32_t))
					return false;

				const uint16_t attributes = *reinterpret_cast<const uint16_t*>(ptr);
				ptr += sizeof(uint16_t); // attributes
				ptr += sizeof(uint32_t); // type index
				remaining -= sizeof(uint16_t) + sizeof(uint32_t);

				const uint8_t method_property = static_cast<uint8_t>((attributes >> 2) & 0x07);
				if (method_property == 4 || method_property == 5 || method_property == 6) {
					if (remaining < sizeof(int32_t))
						return false;

					ptr += sizeof(int32_t);
					remaining -= sizeof(int32_t);
				}

				if (!skip_c_string(ptr, remaining))
					return false;
			}
			else if (leaf == lf_vfunctab) {
				if (remaining < sizeof(uint32_t))
					return false;

				ptr += sizeof(uint32_t);
				remaining -= sizeof(uint32_t);
			}
			else if (leaf == lf_index) {
				if (remaining < sizeof(uint32_t))
					return false;

				ptr += sizeof(uint32_t);
				remaining -= sizeof(uint32_t);
			}
			else {
				Log(L"[-] Unhandled LF_FIELDLIST subtype 0x" << std::hex << leaf << std::dec << std::endl);
				return false;
			}
		}

		return true;
	}

	bool parse_structure(const uint8_t* data, uint32_t size, uint16_t leaf, type_data* type) {
		const uint8_t* ptr = data;
		uint32_t remaining = size;
		if (remaining < sizeof(uint16_t) * 2 + sizeof(uint32_t) * 3)
			return false;

		type->kind = leaf;
		ptr += sizeof(uint16_t); // member count
		type->properties = *reinterpret_cast<const uint16_t*>(ptr);
		ptr += sizeof(uint16_t);
		type->field_list = *reinterpret_cast<const uint32_t*>(ptr);
		ptr += sizeof(uint32_t) * 3; // field list, derived, vshape
		remaining -= sizeof(uint16_t) * 2 + sizeof(uint32_t) * 3;

		uint64_t structure_size = 0;
		if (!parse_cv_integer(ptr, remaining, &structure_size))
			return false;

		if (!read_c_string(ptr, remaining, &type->name))
			return false;

		return true;
	}

	bool parse_tpi(pdb_context* ctx) {
		if (ctx->streams.size() <= tpi_stream || ctx->streams[tpi_stream].data.size() < sizeof(tpi_header))
			return false;

		const auto& stream = ctx->streams[tpi_stream];
		auto header = reinterpret_cast<const tpi_header*>(stream.data.data());
		if (header->header_size < sizeof(tpi_header) ||
			header->type_index_end <= header->type_index_begin ||
			header->header_size + header->type_record_bytes > stream.data.size()) {
			Log(L"[-] Invalid TPI header" << std::endl);
			return false;
		}

		ctx->type_index_begin = header->type_index_begin;
		ctx->types.reserve(header->type_index_end - header->type_index_begin);

		const uint8_t* ptr = stream.data.data() + header->header_size;
		uint32_t remaining = header->type_record_bytes;
		uint32_t index = header->type_index_begin;

		while (remaining >= sizeof(uint16_t) && index < header->type_index_end) {
			const uint16_t record_len = *reinterpret_cast<const uint16_t*>(ptr);
			if (record_len < sizeof(uint16_t) || record_len + sizeof(uint16_t) > remaining)
				return false;

			const uint8_t* record = ptr + sizeof(uint16_t);
			const uint16_t leaf = *reinterpret_cast<const uint16_t*>(record);
			const uint8_t* data = record + sizeof(uint16_t);
			const uint32_t data_size = record_len - sizeof(uint16_t);

			type_data type = {};
			type.index = index;
			type.kind = leaf;

			if (leaf == lf_structure || leaf == lf_class) {
				if (!parse_structure(data, data_size, leaf, &type))
					return false;
			}
			else if (leaf == lf_fieldlist) {
				if (!parse_fieldlist(data, data_size, &type))
					return false;
			}

			ctx->types.push_back(std::move(type));
			ptr += record_len + sizeof(uint16_t);
			remaining -= record_len + sizeof(uint16_t);
			++index;
		}

		return true;
	}

	type_data* find_struct(pdb_context* ctx, const char* name) {
		type_data* forward_ref = nullptr;
		for (auto& type : ctx->types) {
			if ((type.kind != lf_structure && type.kind != lf_class) || type.name != name)
				continue;

			if (type.properties & 0x80) {
				if (!forward_ref)
					forward_ref = &type;
				continue;
			}

			return &type;
		}

		return forward_ref;
	}

	bool resolve_field(pdb_context* ctx, const char* struct_name, const char* field_name, ULONG* out_offset) {
		type_data* structure = find_struct(ctx, struct_name);
		if (!structure) {
			Log(L"[-] Failed to find struct " << struct_name << std::endl);
			return false;
		}

		type_data* field_list = find_type(ctx, structure->field_list);
		if (!field_list || field_list->kind != lf_fieldlist) {
			Log(L"[-] Failed to find field list for " << struct_name << std::endl);
			return false;
		}

		for (const auto& member : field_list->members) {
			if (member.name == field_name) {
				*out_offset = static_cast<ULONG>(member.offset);
				Log(L"[+] " << struct_name << "::" << field_name << L" = 0x" << std::hex << *out_offset << std::dec << std::endl);
				return true;
			}
		}

		Log(L"[-] Failed to resolve " << struct_name << "::" << field_name << std::endl);
		return false;
	}

	bool load_pdb_context(const wchar_t* module_name, pdb_context* ctx, bool parse_types) {
		std::wstring pdb_path;
		if (!find_module_pdb(module_name, &pdb_path))
			return false;

		if (!read_file(pdb_path, &ctx->raw)) {
			Log(L"[-] Failed to read PDB " << pdb_path << std::endl);
			return false;
		}

		Log(L"[+] Parsing PDB " << pdb_path << std::endl);
		if (!parse_streams(ctx))
			return false;

		return !parse_types || parse_tpi(ctx);
	}

	bool resolve_public_symbol_rva_from_context(const wchar_t* module_name, pdb_context* ctx, const char* symbol_name, uint64_t* rva) {
		if (!parse_public_symbols(ctx))
			return false;

		for (const auto& symbol : ctx->public_symbols) {
			if (symbol.name != symbol_name)
				continue;

			uint32_t section_rva = 0;
			if (!get_section_rva(module_name, symbol.segment, &section_rva))
				return false;

			*rva = static_cast<uint64_t>(section_rva) + symbol.offset;
			Log(L"[+] " << module_name << L"!" << symbol_name << L" = rva 0x" << std::hex << *rva << std::dec << std::endl);
			return true;
		}

		Log(L"[-] Failed to resolve public symbol " << symbol_name << L" in " << module_name << std::endl);
		return false;
	}
}

namespace pdb_offsets {
	bool resolve(loader_offsets::block* offsets) {
		if (!offsets)
			return false;

		pdb_context nt_ctx;
		if (!load_pdb_context(L"ntoskrnl.exe", &nt_ctx, true))
			return false;

		loader_offsets::eprocess_offsets resolved = { 0 };
		if (!resolve_field(&nt_ctx, "_EPROCESS", "UniqueProcessId", &resolved.pid) ||
			!resolve_field(&nt_ctx, "_EPROCESS", "ActiveProcessLinks", &resolved.flink) ||
			!resolve_field(&nt_ctx, "_EPROCESS", "ImageFileName", &resolved.image_name) ||
			!resolve_field(&nt_ctx, "_EPROCESS", "ActiveThreads", &resolved.active_threads) ||
			!resolve_field(&nt_ctx, "_KPROCESS", "DirectoryTableBase", &resolved.directory_table_base) ||
			!resolve_field(&nt_ctx, "_EPROCESS", "Peb", &resolved.peb) ||
			!resolve_field(&nt_ctx, "_PEB", "Ldr", &resolved.ldr_data)) {
			return false;
		}

		offsets->eprocess = resolved;

		if (!resolve_public_symbol_rva_from_context(L"ntoskrnl.exe", &nt_ctx, "MmPfnDatabase", &offsets->mm_pfn_database_rva)) {
			Log(L"[-] Failed to resolve ntoskrnl.exe!MmPfnDatabase from PDB" << std::endl);
			return false;
		}

		offsets->mi_get_page_table_pfn_buddy_rva = 0;
		if (!resolve_public_symbol_rva_from_context(L"ntoskrnl.exe", &nt_ctx, "MiGetPageTablePfnBuddyRaw", &offsets->mi_get_page_table_pfn_buddy_rva)) {
			Log(L"[~] ntoskrnl.exe!MiGetPageTablePfnBuddyRaw not found; driver PFN fallback will be used" << std::endl);
		}

		pdb_context win32k_ctx;
		if (!load_pdb_context(L"win32k.sys", &win32k_ctx, false))
			return false;

		if (!resolve_public_symbol_rva_from_context(L"win32k.sys", &win32k_ctx, "NtUserGetCPD", &offsets->nt_user_get_cpd_rva)) {
			Log(L"[-] Failed to resolve win32k.sys!NtUserGetCPD from PDB" << std::endl);
			return false;
		}

		return true;
	}

	uint64_t get_symbol_offset(const wchar_t* module_name, const char* symbol_name) {
		static std::unordered_map<std::wstring, pdb_context> ctx_cache;
		std::wstring mod_key = module_name;

		if (ctx_cache.find(mod_key) == ctx_cache.end()) {
			pdb_context new_ctx;
			if (!load_pdb_context(module_name, &new_ctx, false)) {
				return 0;
			}
			ctx_cache[mod_key] = std::move(new_ctx);
		}

		uint64_t rva = 0;
		if (resolve_public_symbol_rva_from_context(module_name, &ctx_cache[mod_key], symbol_name, &rva)) {
			return rva;
		}

		return 0;
	}
}
