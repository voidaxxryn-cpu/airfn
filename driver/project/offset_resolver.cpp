#include "offset_resolver.hpp"
#include "project_includes.hpp"
#include <ntddk.h>

namespace offset_resolver {

    eprocess_offsets g_offsets = { 0 };
    loader_offsets::block* g_loader_offsets_block = nullptr;

    static bool initialized = false;

    NTSTATUS initialize_offsets_from_mapper(loader_offsets::block* loader_offsets_block, ULONG64 driver_size) {
        if (!loader_offsets_block) {
            DbgPrint("[OffsetResolver] ERROR: Invalid loader_offsets block pointer - mapper loading required!\n");
            return STATUS_INVALID_PARAMETER;
        }

        if (loader_offsets_block->magic != loader_offsets::magic) {
            DbgPrint("[OffsetResolver] ERROR: Invalid loader_offsets magic: 0x%X (expected 0x%X)\n",
                loader_offsets_block->magic, loader_offsets::magic);
            return STATUS_INVALID_PARAMETER;
        }

        if (loader_offsets_block->version != loader_offsets::version) {
            DbgPrint("[OffsetResolver] ERROR: Unsupported loader_offsets version: %lu (expected %lu)\n",
                loader_offsets_block->version, loader_offsets::version);
            return STATUS_INVALID_PARAMETER;
        }

        // Copy PDB-resolved offsets from mapper's block
        g_offsets.pid = loader_offsets_block->eprocess.pid;
        g_offsets.flink = loader_offsets_block->eprocess.flink;
        g_offsets.image_name = loader_offsets_block->eprocess.image_name;
        g_offsets.active_threads = loader_offsets_block->eprocess.active_threads;
        g_offsets.directory_table_base = loader_offsets_block->eprocess.directory_table_base;
        g_offsets.peb = loader_offsets_block->eprocess.peb;
        g_offsets.ldr_data = loader_offsets_block->eprocess.ldr_data;

        g_loader_offsets_block = loader_offsets_block;
        g_driver_size = driver_size;
        initialized = true;

        DbgPrint("[OffsetResolver] SUCCESS: Initialized from mapper's PDB-resolved offsets\n");
        DbgPrint("  EPROCESS.UniqueProcessId: 0x%X\n", g_offsets.pid);
        DbgPrint("  EPROCESS.ActiveProcessLinks.Flink: 0x%X\n", g_offsets.flink);
        DbgPrint("  EPROCESS.ImageFileName: 0x%X\n", g_offsets.image_name);
        DbgPrint("  EPROCESS.ActiveThreads: 0x%X\n", g_offsets.active_threads);
        DbgPrint("  KPROCESS.DirectoryTableBase: 0x%X\n", g_offsets.directory_table_base);
        DbgPrint("  EPROCESS.Peb: 0x%X\n", g_offsets.peb);
        DbgPrint("  PEB.Ldr: 0x%X\n", g_offsets.ldr_data);
        DbgPrint("  MmPfnDatabase RVA: 0x%llX\n", loader_offsets_block->mm_pfn_database_rva);
        DbgPrint("  MiGetPageTablePfnBuddyRaw RVA: 0x%llX\n", loader_offsets_block->mi_get_page_table_pfn_buddy_rva);
        DbgPrint("  NtUserGetCPD RVA: 0x%llX\n", loader_offsets_block->nt_user_get_cpd_rva);
        DbgPrint("  Driver Size: 0x%llX\n", g_driver_size);

        return STATUS_SUCCESS;
    }

    NTSTATUS initialize_offsets() {
        return STATUS_NOT_SUPPORTED;
    }

    bool is_initialized() {
        return initialized;
    }
}
