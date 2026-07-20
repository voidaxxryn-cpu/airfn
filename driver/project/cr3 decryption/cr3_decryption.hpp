#pragma once
#include "../project_api.hpp"
#include "../project_utility.hpp"
#include "../communication/shared_structs.hpp"

#pragma warning(push)
#pragma warning(disable:4201)

/**
 * @brief Structure for a Memory Page Frame Node (_MMPFN).
 *
 * This structure is used to represent a page frame in memory. It holds several fields, including
 * flags and the address of the Page Table Entry (PTE).
 */
struct _MMPFN {
    uintptr_t flags; /**< Flags associated with the page frame */
    uintptr_t pte_address; /**< Address of the Page Table Entry (PTE) for this page frame */
    uintptr_t Unused_1; /**< Reserved field */
    uintptr_t Unused_2; /**< Reserved field */
    uintptr_t Unused_3; /**< Reserved field */
    uintptr_t Unused_4; /**< Reserved field */
};
static_assert(sizeof(_MMPFN) == 0x30, "Size of _MMPFN structure is not 0x30");

/**
 * @brief Operator for converting a size in MiB to bytes.
 *
 * This operator allows for easy conversion between megabytes (MiB) and bytes.
 *
 * @param num The number of MiB to convert.
 * @return The size in bytes.
 */
constexpr size_t operator ""_MiB(size_t num) { return num << 20; }

/**
 * @brief Enumeration for iteration statuses.
 *
 * This enum defines possible statuses for an iteration process, indicating whether to continue
 * or stop the iteration.
 */
enum iteration_status {
    status_stop_iteration, /**< Indicates that the iteration should stop */
    status_continue_iteration /**< Indicates that the iteration should continue */
};

/**
 * @namespace cr3_decryption
 *
 * This namespace contains functions and methods related to CR3 decryption, which is typically used
 * in kernel-mode code for accessing process memory. It provides methods for accessing the CR3
 * register, retrieving process IDs, and accessing PEB information.
 */
namespace cr3_decryption {

    //win11 23h2-25h2 :((
    static uint64_t(__fastcall* g_MiGetPageTablePfnBuddyRaw)(const _MMPFN&) = nullptr;

    /**
     * @brief Initialization function for CR3 decryption.
     *
     * This function is used to initialize the CR3 decryption process.
     *
     * @return A project_status code indicating success or failure.
     */
    project_status init_eac_cr3_decryption(void);

    /**
     * @namespace eproc
     *
     * This sub-namespace provides functions for dealing with process-related information
     * in the context of CR3 decryption.
     */
    namespace eproc {

        /**
         * @brief Retrieves the CR3 value of a process given its PID.
         *
         * This function is used to retrieve the CR3 register value of a process, which points
         * to the page directory of the target process.
         *
         * @param target_pid The Process ID (PID) of the target process.
         * @return The CR3 register value of the process.
         */
        uint64_t get_cr3(uint64_t target_pid);

        /**
         * @brief Retrieves the PID of a process given its name.
         *
         * This function is used to find the Process ID (PID) of a target process by its name.
         *
         * @param target_process_name The name of the target process.
         * @return The PID of the target process.
         */
        uint64_t get_pid(const char* target_process_name);
    };

    /**
     * @namespace peb
     *
     * This sub-namespace provides functions for accessing the Process Environment Block (PEB)
     * and its associated data for a given process.
     */
    namespace peb {

        /**
         * @brief Retrieves data table entry information for a target process.
         *
         * This function is used to retrieve the entries in the data table for a specific process.
         * The data is returned in an array of `module_info_t` structures.
         *
         * @param target_pid The Process ID (PID) of the target process.
         * @param info_array An array to store the module information.
         * @param proc_cr3 The CR3 value of the process.
         * @return A project_status code indicating success or failure.
         */
        project_status get_data_table_entry_info(uint64_t target_pid, module_info_t* info_array, uint64_t proc_cr3);

        /**
         * @brief Retrieves the number of data table entries for a target process.
         *
         * This function returns the number of entries in the data table of the target process.
         *
         * @param target_pid The Process ID (PID) of the target process.
         * @return The number of data table entries for the target process.
         */
        uint64_t get_data_table_entry_count(uint64_t target_pid);

        /**
         * @brief Retrieves the base address of a module in a target process.
         *
         * This function returns the base address of a specific module in the target process.
         *
         * @param target_pid The Process ID (PID) of the target process.
         * @param module_name The name of the module to look for.
         * @return The base address of the specified module.
         */
        uint64_t get_module_base(uint64_t target_pid, char* module_name);

        /**
         * @brief Retrieves the size of a module in a target process.
         *
         * This function returns the size of a specific module in the target process.
         *
         * @param target_pid The Process ID (PID) of the target process.
         * @param module_name The name of the module to look for.
         * @return The size of the specified module in bytes.
         */
        uint64_t get_module_size(uint64_t target_pid, char* module_name);
    };
}
