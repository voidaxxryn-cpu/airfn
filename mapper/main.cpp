#include <Windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <TlHelp32.h>

#include "includes/kdmapper.hpp"
#include "includes/utils.hpp"
#include "includes/intel_driver.hpp"
#include "includes/loader_offsets.hpp"
#include "includes/pdb_offsets.hpp"

namespace {
	loader_offsets::block g_loader_offsets = { 0 };
	ULONG64 g_remote_loader_offsets = 0;
}

LONG WINAPI SimplestCrashHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
	if (ExceptionInfo && ExceptionInfo->ExceptionRecord)
		Log(L"[!!] Crash at addr 0x" << ExceptionInfo->ExceptionRecord->ExceptionAddress << L" by 0x" << std::hex << ExceptionInfo->ExceptionRecord->ExceptionCode << std::endl);
	else
		Log(L"[!!] Crash" << std::endl);

	if (intel_driver::hDevice)
		intel_driver::Unload();

	return EXCEPTION_EXECUTE_HANDLER;
}

int paramExists(const int argc, wchar_t** argv, const wchar_t* param) {
	size_t plen = wcslen(param);
	for (int i = 1; i < argc; i++) {
		if (wcslen(argv[i]) == plen + 1ull && _wcsicmp(&argv[i][1], param) == 0 && argv[i][0] == '/') { // with slash
			return i;
		}
		else if (wcslen(argv[i]) == plen + 2ull && _wcsicmp(&argv[i][2], param) == 0 && argv[i][0] == '-' && argv[i][1] == '-') { // with double dash
			return i;
		}
	}
	return -1;
}

bool callbackExample(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize) {
	g_loader_offsets.driver_size = allocationSize;

	g_remote_loader_offsets = intel_driver::AllocatePool(nt::POOL_TYPE::NonPagedPool, sizeof(g_loader_offsets));
	if (!g_remote_loader_offsets) {
		Log(L"[-] Failed to allocate loader offset block" << std::endl);
		return false;
	}

	if (!intel_driver::WriteMemory(g_remote_loader_offsets, &g_loader_offsets, sizeof(g_loader_offsets))) {
		Log(L"[-] Failed to write loader offset block" << std::endl);
		intel_driver::FreePool(g_remote_loader_offsets);
		g_remote_loader_offsets = 0;
		return false;
	}

	*param1 = allocationPtr;
	*param2 = g_remote_loader_offsets;
	Log(L"[+] Loader offset block written at 0x" << reinterpret_cast<void*>(g_remote_loader_offsets) << std::endl);
	Log(L"[*] Loader offsets: magic=0x" << std::hex << g_loader_offsets.magic
		<< L" version=" << std::dec << g_loader_offsets.version
		<< L" size=" << g_loader_offsets.size
		<< L" driver_size=0x" << std::hex << g_loader_offsets.driver_size
		<< L" ntuser=0x" << g_loader_offsets.nt_user_get_cpd_rva
		<< L" mmpfn=0x" << g_loader_offsets.mm_pfn_database_rva
		<< L" buddy=0x" << g_loader_offsets.mi_get_page_table_pfn_buddy_rva
		<< std::dec << std::endl);
	return true;
}

DWORD getParentProcess()
{
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD ppid = 0, pid = GetCurrentProcessId();

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	__try {
		if (hSnapshot == INVALID_HANDLE_VALUE || hSnapshot == 0) __leave;

		ZeroMemory(&pe32, sizeof(pe32));
		pe32.dwSize = sizeof(pe32);
		if (!Process32First(hSnapshot, &pe32)) __leave;

		do {
			if (pe32.th32ProcessID == pid) {
				ppid = pe32.th32ParentProcessID;
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));

	}
	__finally {
		if (hSnapshot != INVALID_HANDLE_VALUE && hSnapshot != 0) CloseHandle(hSnapshot);
	}
	return ppid;
}

//Help people that don't understand how to open a console
void PauseIfParentIsExplorer() {
	DWORD explorerPid = 0;
	GetWindowThreadProcessId(GetShellWindow(), &explorerPid);
	DWORD parentPid = getParentProcess();
	if (parentPid == explorerPid) {
		Log(L"[+] Pausing to allow for debugging" << std::endl);
		Log(L"[+] Press enter to close" << std::endl);
		std::cin.get();
	}
}

void help() {
	Log(L"\r\n\r\n[!] Incorrect Usage!" << std::endl);
	Log(L"[+] Usage: kdmapper.exe [--free | --indPages][--PassAllocationPtr][--copy-header]");
	
	Log(L" driver" << std::endl);

	PauseIfParentIsExplorer();
}

int wmain(const int argc, wchar_t** argv) {
	SetUnhandledExceptionFilter(SimplestCrashHandler);

	bool free = paramExists(argc, argv, L"free") > 0;
	bool indPagesMode = paramExists(argc, argv, L"indPages") > 0;
	bool passAllocationPtr = paramExists(argc, argv, L"PassAllocationPtr") > 0;
	bool copyHeader = paramExists(argc, argv, L"copy-header") > 0;
	bool resolveOnly = paramExists(argc, argv, L"resolve-only") > 0;

	if (free) {
		Log(L"[+] Free pool memory after usage enabled" << std::endl);
	}

	if (indPagesMode) {
		Log(L"[+] Allocate Independent Pages mode enabled" << std::endl);
	}

	if (free && indPagesMode) {
		Log(L"[-] Can't use --free and --indPages at the same time" << std::endl);
		help();
		return -1;
	}

	if (passAllocationPtr) {
		Log(L"[+] Pass Allocation Ptr as first param enabled" << std::endl);
	}

	if (copyHeader) {
		Log(L"[+] Copying driver header enabled" << std::endl);
	}

	if (resolveOnly) {
		Log(L"[+] Resolve-only mode enabled" << std::endl);
	}

	int drvIndex = -1;
	for (int i = 1; i < argc; i++) {
		if (std::filesystem::path(argv[i]).extension().string().compare(".sys") == 0) {
			drvIndex = i;
			break;
		}
	}

	if (drvIndex <= 0) {
		help();
		return -1;
	}

	const std::wstring driver_path = argv[drvIndex];

	if (!std::filesystem::exists(driver_path)) {
		Log(L"[-] File " << driver_path << L" doesn't exist" << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}

	g_loader_offsets.magic = loader_offsets::magic;
	g_loader_offsets.version = loader_offsets::version;
	g_loader_offsets.size = sizeof(g_loader_offsets);

	if (!pdb_offsets::resolve(&g_loader_offsets)) {
		Log(L"[-] Failed to resolve loader data from PDB" << std::endl);
		PauseIfParentIsExplorer();
		return -1;
	}

	if (resolveOnly) {
		Log(L"[+] PDB offset resolve succeeded" << std::endl);
		return 0;
	}

	if (!intel_driver::Load()) {
		PauseIfParentIsExplorer();
		return -1;
	}

	std::vector<uint8_t> raw_image = { 0 };
	if (!utils::ReadFileToMemory(driver_path, &raw_image)) {
		Log(L"[-] Failed to read image to memory" << std::endl);
		intel_driver::Unload();
		PauseIfParentIsExplorer();
		return -1;
	}

	kdmapper::AllocationMode mode = kdmapper::AllocationMode::AllocateContiguousMemory;

	bool free_mem = false; //change it to false if we're using the driver api call -> hide_driver
	bool remove_from_system_page_tables = false; //change it to false if we're using the driver api call -> hide_driver
	bool destroy_header = false;
	bool pass_allocation = true;
	bool pass_size = true;

	if (indPagesMode) {
		mode = kdmapper::AllocationMode::AllocateIndependentPages;
	}

	NTSTATUS exitCode = 0;
	if (!kdmapper::MapDriver(raw_image.data(), 0, 0, free_mem, remove_from_system_page_tables, destroy_header, mode, pass_allocation, pass_size, callbackExample, &exitCode)) {
		Log(L"[-] Failed to map " << driver_path << std::endl);
		if (g_remote_loader_offsets) {
			intel_driver::FreePool(g_remote_loader_offsets);
			g_remote_loader_offsets = 0;
		}
		intel_driver::Unload();
		PauseIfParentIsExplorer();
		return -1;
	}

	if (!NT_SUCCESS(exitCode)) {
		Log(L"[-] DriverEntry failed with 0x" << std::hex << exitCode << std::dec << std::endl);
		if (g_remote_loader_offsets) {
			intel_driver::FreePool(g_remote_loader_offsets);
			g_remote_loader_offsets = 0;
		}
		intel_driver::Unload();
		PauseIfParentIsExplorer();
		return -1;
	}

	if (g_remote_loader_offsets) {
		intel_driver::FreePool(g_remote_loader_offsets);
		g_remote_loader_offsets = 0;
	}

	if (!intel_driver::Unload()) {
		Log(L"[-] Warning failed to fully unload vulnerable driver " << std::endl);
		PauseIfParentIsExplorer();
	}
	Log(L"[+] success" << std::endl);

}
