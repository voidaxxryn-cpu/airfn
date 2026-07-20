#pragma once
#include <ntddk.h>
#include <intrin.h>

#include "windows_structs.hpp"

// We like nice declarations
typedef signed char        int8_t;        /**< Signed 8-bit integer */
typedef short              int16_t;       /**< Signed 16-bit integer */
typedef int                int32_t;       /**< Signed 32-bit integer */
typedef long long          int64_t;       /**< Signed 64-bit integer */
typedef unsigned char      uint8_t;       /**< Unsigned 8-bit integer */
typedef unsigned short     uint16_t;      /**< Unsigned 16-bit integer */
typedef unsigned int       uint32_t;      /**< Unsigned 32-bit integer */
typedef unsigned long long uint64_t;      /**< Unsigned 64-bit integer */

#ifndef MAXULONG32
#define MAXULONG32 0x00000000ffffffffUL
#endif

#ifndef MAXULONG64
#define MAXULONG64 0xffffffffffffffffui64
#endif

/**
 * @brief Enum for project return status codes.
 *
 * This enum defines various return status codes used across the project to indicate
 * different result states such as success, failure, invalid parameters, or memory allocation issues.
 */
enum project_status {
    /** General status codes */
    status_success,                       /**< Operation was successful */
    status_failure,                       /**< Operation failed */
    status_invalid_parameter,            /**< Invalid parameter provided */
    status_memory_allocation_failed,     /**< Memory allocation failed */
    status_win_address_translation_failed, /**< Windows address translation failed */
    status_not_supported,                /**< Operation not supported */

    /** Windows-specific status codes */
    status_cr3_not_found,                /**< CR3 register could not be found */

    /** Physical memory management status codes */
    status_invalid_paging_idx,           /**< Invalid paging index */
    status_paging_entry_not_present,     /**< Paging entry not present */
    status_remapping_entry_found,        /**< Remapping entry found */
    status_no_valid_remapping_entry,     /**< No valid remapping entry found */
    status_no_available_page_tables,    /**< No available page tables */
    status_remapping_list_full,          /**< Remapping list is full */
    status_wrong_context,                /**< Wrong context detected */
    status_invalid_my_page_table,        /**< Invalid page table found */
    status_address_already_remapped,     /**< Address already remapped */
    status_non_aligned,                  /**< Address is not aligned */
    status_paging_wrong_granularity,     /**< Paging granularity is wrong */
    status_page_already_unmapped,       /**< Page is already unmapped */
    status_potential_mem_unmapping_overflow, /**< Potential memory unmapping overflow */

    /** Communication-related status codes */
    status_data_ptr_invalid,             /**< Invalid data pointer */
    status_no_gadget_found,              /**< No gadget found */
};

 /**
  * @brief Logging macro for error messages.
  *
  * This macro logs error messages with the file name and line number.
  *
  * @param fmt Format string for the message.
  * @param ... Arguments for the format string.
  */
#define project_log_error(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] " "[%s:%d] " fmt "\n",  __LINE__, ##__VA_ARGS__)

  /**
   * @brief Logging macro for warning messages.
   *
   * This macro logs warning messages with the file name and line number.
   *
   * @param fmt Format string for the message.
   * @param ... Arguments for the format string.
   */
#define project_log_warning(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[~] " "[%s:%d] " fmt "\n",  __LINE__, ##__VA_ARGS__)

   /**
    * @brief Logging macro for success messages.
    *
    * This macro logs success messages with the file name and line number.
    *
    * @param fmt Format string for the message.
    * @param ... Arguments for the format string.
    */
#define project_log_success(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] " "[%s:%d] " fmt "\n",  __LINE__, ##__VA_ARGS__)

    /**
     * @brief Logging macro for informational messages.
     *
     * This macro logs informational messages with the file name and line number.
     *
     * @param fmt Format string for the message.
     * @param ... Arguments for the format string.
     */
#define project_log_info(fmt, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[*] " "[%s:%d] " fmt "\n",  __LINE__, ##__VA_ARGS__)

     /**
      * @brief Wrapper function to get the physical address of a virtual address.
      *
      * This function returns the physical address corresponding to the given virtual address.
      *
      * @param virtual_address The virtual address to convert.
      * @return The physical address corresponding to the given virtual address.
      */
inline uint64_t win_get_physical_address(void* virtual_address) {
    return MmGetPhysicalAddress(virtual_address).QuadPart;
}

/**
 * @brief Wrapper function to get the virtual address corresponding to a physical address.
 *
 * This function returns the virtual address corresponding to the given physical address.
 *
 * @param physical_address The physical address to convert.
 * @return The virtual address corresponding to the given physical address.
 */
inline uint64_t win_get_virtual_address(uint64_t physical_address) {
    PHYSICAL_ADDRESS phys_addr = { 0 };
    phys_addr.QuadPart = physical_address;

    return (uint64_t)(MmGetVirtualForPhysical(phys_addr));
}

/**
 * @brief Wrapper function to sleep for a specified number of milliseconds.
 *
 * This function puts the calling thread to sleep for a specified duration in milliseconds.
 *
 * @param milliseconds The duration in milliseconds to sleep.
 */
inline void sleep(LONG milliseconds) {
    LARGE_INTEGER interval;

    // Convert milliseconds to 100-nanosecond intervals
    interval.QuadPart = -((LONGLONG)milliseconds * 10000);

    KeDelayExecutionThread(KernelMode, false, &interval);
}

/**
 * @brief External declaration for a function to get the process number.
 *
 * This function retrieves the process number.
 *
 * @return The process number.
 */
extern "C" uint32_t get_proc_number(void);

/**
 * @brief External declaration for an assembly handler function.
 *
 * This function serves as a handler for assembly-level operations.
 */
extern "C" void asm_handler(void);

/**
 * @brief External declaration for the `KeStackAttachProcess` function.
 *
 * This function attaches the current thread to the specified process's address space.
 *
 * @param PROCESS A pointer to the process to attach to.
 * @param ApcState A pointer to the APC state for the thread.
 */
extern "C" NTKERNELAPI VOID KeStackAttachProcess(PRKPROCESS PROCESS, PKAPC_STATE ApcState);

/**
 * @brief External declaration for the `KeUnstackDetachProcess` function.
 *
 * This function detaches the current thread from the address space of the attached process.
 *
 * @param ApcState A pointer to the APC state for the thread.
 */
extern "C" NTKERNELAPI VOID KeUnstackDetachProcess(PKAPC_STATE ApcState);

/**
 * @brief External declaration for the PsLoadedModuleList symbol.
 *
 * This symbol provides access to the list of loaded modules in the system.
 */
extern "C" PLIST_ENTRY PsLoadedModuleList;

/**
 * @brief Global variable for the base address of the driver.
 *
 * This variable holds the base address of the loaded driver in memory.
 */
inline void* g_driver_base;

/**
 * @brief Global variable for the size of the driver.
 *
 * This variable holds the size of the loaded driver.
 */
inline uint64_t g_driver_size;

/**
 * @brief Session ID of the process that loaded the driver.
 *
 * Captured at driver_entry from the loader's process. Used to find the winlogon
 * process in that session for win32k data-pointer hook installation, since
 * win32k data is session-private.
 */
inline ULONG g_target_session_id = 0;

