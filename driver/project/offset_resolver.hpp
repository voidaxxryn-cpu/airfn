#pragma once
#include <ntddk.h>
#include "loader_offsets.hpp"

// Declare undocumented Windows kernel functions
extern "C" PUCHAR NTAPI PsGetProcessImageFileName(PEPROCESS Process);


namespace offset_resolver {

    /**
     * @brief Structure to hold all dynamically resolved offsets
     */
    struct eprocess_offsets {
        unsigned long image_name;          /**< Offset for ImageFileName in EPROCESS */
        unsigned long pid;                 /**< Offset for UniqueProcessId in EPROCESS */
        unsigned long flink;               /**< Offset for ActiveProcessLinks.Flink in EPROCESS */
        unsigned long directory_table_base;/**< Offset for DirectoryTableBase in EPROCESS */
        unsigned long peb;                 /**< Offset for Peb in EPROCESS */
        unsigned long active_threads;      /**< Offset for ActiveThreads in EPROCESS */
        unsigned long ldr_data;            /**< Offset for Ldr in PEB */
    };

    /**
     * @brief Global structure containing all resolved offsets
     */
    extern eprocess_offsets g_offsets;

    /**
     * @brief Global loader offsets block from mapper with PDB-resolved RVAs
     */
    extern loader_offsets::block* g_loader_offsets_block;

    /**
     * @brief Get the PDB-resolved MmPfnDatabase RVA
     * @return RVA (relative virtual address) of MmPfnDatabase in ntoskrnl.exe
     */
    inline ULONG64 get_mm_pfn_database_rva() {
        return g_loader_offsets_block ? g_loader_offsets_block->mm_pfn_database_rva : 0;
    }

    /**
     * @brief Get the PDB-resolved MiGetPageTablePfnBuddyRaw RVA
     * @return RVA of MiGetPageTablePfnBuddyRaw in ntoskrnl.exe
     */
    inline ULONG64 get_mi_get_page_table_pfn_buddy_rva() {
        return g_loader_offsets_block ? g_loader_offsets_block->mi_get_page_table_pfn_buddy_rva : 0;
    }

    /**
     * @brief Get the PDB-resolved NtUserGetCPD RVA
     * @return RVA of NtUserGetCPD in win32k.sys
     */
    inline ULONG64 get_nt_user_get_cpd_rva() {
        return g_loader_offsets_block ? g_loader_offsets_block->nt_user_get_cpd_rva : 0;
    }

    /**
     * @brief Initialize offsets from mapper (REQUIRED)
     *
     * This function MUST be called during driver initialization.
     * The driver requires mapper loading with PDB-resolved offsets.
     *
     * @param loader_offsets_block Pointer to loader_offsets::block in kernel memory
     * @param driver_size Size of the driver allocation
     * @return STATUS_SUCCESS on success, error code otherwise
     */
    NTSTATUS initialize_offsets_from_mapper(loader_offsets::block* loader_offsets_block, ULONG64 driver_size);

    /**
     * @brief Placeholder - direct loading not supported
     * @return STATUS_NOT_SUPPORTED
     */
    NTSTATUS initialize_offsets();


    /**
     * @brief Checks if offsets have been initialized
     *
     * @return true if offsets are initialized, false otherwise
     */
    bool is_initialized();

} // namespace offset_resolver

