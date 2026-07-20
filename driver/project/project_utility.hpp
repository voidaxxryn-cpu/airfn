#ifndef PROJECT_UTILITY_HPP
#define PROJECT_UTILITY_HPP

#include "project_includes.hpp"

/**
 * @namespace utility
 * @brief Namespace containing utility functions for project-related tasks.
 *
 * This namespace exposes functions that assist with various operations such as
 * retrieving the module base of a driver, searching for patterns in memory regions,
 * and interacting with process structures.
 */
namespace utility {

    /**
     * @brief Retrieves the base address of a loaded driver module.
     *
     * This function searches for a driver by name and returns its base address.
     *
     * @param driver_name The name of the driver module to search for.
     * @param driver_base A reference to a pointer where the base address of the driver will be stored.
     * @return project_status A status indicating whether the operation succeeded or failed.
     */
    project_status get_driver_module_base(const wchar_t* driver_name, void*& driver_base);

    /**
     * @brief Retrieves the EPROCESS structure for a given process by name.
     *
     * This function retrieves the EPROCESS structure for a process based on its name.
     * The EPROCESS structure provides detailed information about the process.
     *
     * @param process_name The name of the process to search for.
     * @param pe_proc A reference to a PEPROCESS pointer that will hold the process's EPROCESS structure.
     * @return project_status A status indicating whether the operation succeeded or failed.
     */
    project_status get_eprocess(const char* process_name, PEPROCESS& pe_proc);

    /**
     * @brief Retrieves the EPROCESS structure for a process matching both name and session ID.
     *
     * Used to find a per-session process (e.g. winlogon.exe in the user's session) when
     * the global process list contains multiple instances across sessions.
     *
     * @param process_name The name of the process to search for.
     * @param session_id The target session ID.
     * @param pe_proc A reference to a PEPROCESS pointer that will hold the EPROCESS on success.
     * @return project_status A status indicating whether the operation succeeded or failed.
     */
    project_status get_eprocess_in_session(const char* process_name, ULONG session_id, PEPROCESS& pe_proc);

    /**
     * @brief Checks if a given data pointer lies within a valid memory region.
     *
     * This function validates if the specified data pointer points to a valid region
     * of memory by checking against known valid regions.
     *
     * @param data_ptr The pointer to check.
     * @return project_status A status indicating whether the data pointer is in a valid region.
     */
    project_status is_data_ptr_in_valid_region(uint64_t data_ptr);

    /**
     * @brief Retrieves the CR3 register value (page directory base) for a given process.
     *
     * This function extracts the CR3 value for a specific process identified by its PID.
     * The CR3 value is crucial for memory management and virtual to physical address translation.
     *
     * @param target_pid The PID of the target process.
     * @return uint64_t The CR3 value for the target process.
     */
    uint64_t get_cr3(uint64_t target_pid);

    /**
     * @brief Finds a pattern in a specified range of memory.
     *
     * This function searches for a byte pattern in a given memory range. It supports the use
     * of a wildcard character for pattern matching.
     *
     * @param region_base The base address of the memory region to search.
     * @param region_size The size of the memory region to search.
     * @param pattern The pattern to search for.
     * @param pattern_size The size of the pattern.
     * @param wildcard The wildcard character used for pattern matching (e.g., '?').
     * @return uintptr_t The address where the pattern was found, or 0 if not found.
     */
    uintptr_t find_pattern_in_range(uintptr_t region_base, size_t region_size, const char* pattern, size_t pattern_size, char wildcard);

    /**
     * @brief Searches for a pattern in a section of a loaded module.
     *
     * This function searches for a byte pattern within a specific section of a loaded
     * module in memory.
     *
     * @param module_handle A handle to the loaded module.
     * @param section_name The name of the section to search in.
     * @param pattern The pattern to search for.
     * @param pattern_size The size of the pattern.
     * @param wildcard The wildcard character used for pattern matching (e.g., '?').
     * @return uintptr_t The address where the pattern was found, or 0 if not found.
     */
    uintptr_t search_pattern_in_section(void* module_handle, const char* section_name, const char* pattern, uint64_t pattern_size, char wildcard);

    /**
     * @brief Maps a KnownDll image into the current process.
     *
     * @param dll_name Name of the dll in the KnownDlls namespace.
     * @param module_base Receives mapped image base on success.
     * @return project_status Success if mapping succeeded.
     */
    project_status map_module_from_known_dll(const wchar_t* dll_name, void*& module_base);

    /**
     * @brief Unmaps a previously mapped image view.
     *
     * @param module_base Base address returned by map_module_from_known_dll.
     */
    void unmap_module_view(void* module_base);

    /**
     * @brief Resolves an exported symbol from a PE image base.
     *
     * @param module_base Base address of the PE image.
     * @param function_name Export name to resolve.
     * @return Resolved address, or 0 if not found.
     */
    void* get_export_address(void* module_base, const char* function_name);

    /**
     * @brief Resolves the win32k shadow service table export.
     *
     * @param service_table Receives the W32pServiceTable address.
     * @return project_status Success if resolved.
     */
    project_status get_win32k_service_table(void*& service_table);

    /**
     * @brief Reads the win32k syscall number from the win32u usermode stub.
     *
     * @param function_name Nt* export name in win32u.dll.
     * @param syscall_number Receives syscall index on success.
     * @return project_status Success if resolved.
     */
    project_status get_win32k_syscall_number(const char* function_name, uint32_t& syscall_number);

    /**
     * @brief Resolves the kernel win32k routine address from shadow SSDT.
     *
     * @param win32k_sdt W32pServiceTable address.
     * @param function_name Nt* export name (can be null if syscall_number provided).
     * @param syscall_number Optional syscall number.
     * @param routine Receives routine address on success.
     * @return project_status Success if resolved.
     */
    project_status get_win32k_syscall_routine(void* win32k_sdt, const char* function_name, uint32_t syscall_number, void*& routine);
}; // namespace utility

#endif // PROJECT_UTILITY_HPP
