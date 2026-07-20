#include "project/project_api.hpp"
#include "project/offset_resolver.hpp"

extern "C" NTKERNELAPI ULONG PsGetProcessSessionId(_In_ PEPROCESS Process);

/**
 * @brief Driver entry point for initialization and setup.
 *
 * This driver REQUIRES loading via mapper.exe with PDB-resolved offsets.
 * Direct loading is not supported.
 *
 * @param driver_base Allocation pointer from mapper
 * @param loader_offsets_block Pointer to loader_offsets::block with PDB-resolved offsets
 */
NTSTATUS driver_entry(void* driver_base, uint64_t loader_offsets_block_ptr) {
    project_log_success("Driver loaded via mapper at %p", driver_base);

    if (!driver_base) {
        project_log_error("Invalid driver_base parameter");
        return STATUS_UNSUCCESSFUL;
    }

    g_driver_base = driver_base;
    g_target_session_id = PsGetProcessSessionId(PsGetCurrentProcess());
    project_log_info("Driver loader session_id=%lu", g_target_session_id);

    // mapper MUST provide loader_offsets::block with PDB-resolved offsets
    auto loader_offsets_block = reinterpret_cast<loader_offsets::block*>(loader_offsets_block_ptr);

    NTSTATUS nt_status = offset_resolver::initialize_offsets_from_mapper(loader_offsets_block, loader_offsets_block->driver_size);
    if (!NT_SUCCESS(nt_status)) {
        project_log_error("Failed to initialize offsets from mapper with status 0x%X", nt_status);
        project_log_error("Driver REQUIRES loading via: mapper.exe roseware_driver.sys");
        return STATUS_UNSUCCESSFUL;
    }

    project_status status = status_success;

    // Initialize the physical memory subsystem
    status = physmem::init_physmem();
    if (status != status_success) {
        project_log_error("Failed to init physmem with status %d", status);
        return STATUS_UNSUCCESSFUL;
    }

    // Initialize the CR3 decryption subsystem
    status = cr3_decryption::init_eac_cr3_decryption();
    if (status != status_success) {
        project_log_error("Failed to init CR3 decryption with status %d", status);
        return STATUS_UNSUCCESSFUL;
    }

    // Initialize logging subsystem
    status = logging::init_root_logger();
    if (status != status_success) {
        project_log_error("Failed to init logger with status %d", status);
        return STATUS_UNSUCCESSFUL;
    }

    // Initialize the communication subsystem with PDB-resolved NtUserGetCPD RVA
    status = communication::init_communication(driver_base, g_driver_size);
    if (status != status_success) {
        project_log_error("Failed to init communication with status %d", status);
        return STATUS_UNSUCCESSFUL;
    }

    // Log that the initialization was successful
    project_log_success("Driver initialization finished successfully");

    return STATUS_SUCCESS;
}
