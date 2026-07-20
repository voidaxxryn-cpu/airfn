#pragma once
#pragma optimize("", off)
// Designed to be a standalone, includable .hpp, thus we need to make our own definitions etc.

/**
 * @file shared_structs.hpp
 * @brief This file contains the definitions for communication structures, typedefs, and other helper macros.
 */

 /*
     Typedefs and Definitions
 */

 /**
  * @brief Defines a macro for marking input parameters.
  *
  * This macro is defined to allow function parameters to be marked as input,
  * but is typically used in an environment where Microsoft-specific annotations
  * are not available.
  */
#ifndef _In_
#define _In_
#endif // !_In_

  /**
   * @brief Defines a macro for marking output parameters.
   *
   * This macro is defined to allow function parameters to be marked as output,
   * but is typically used in an environment where Microsoft-specific annotations
   * are not available.
   */
#ifndef _Out_
#define _Out_
#endif // !_Out_

   /**
    * @brief Defines a constant for the maximum path length.
    *
    * This constant is used to define the maximum number of characters allowed
    * for a file or module path.
    */
#ifndef MAX_PATH
#define MAX_PATH 260
#endif // !MAX_PATH

    /**
     * @brief Typedefs for standard unsigned integer types.
     */
using uint8_t = unsigned char; ///< 8-bit unsigned integer
using uint16_t = unsigned short; ///< 16-bit unsigned integer
using uint32_t = unsigned int; ///< 32-bit unsigned integer
using uint64_t = unsigned long long; ///< 64-bit unsigned integer

/*
    Communication structs
*/

/**
 * @brief Structure to hold information about copying virtual memory between different CR3s.
 *
 * This structure is used to define the source and destination CR3s, as well as
 * the memory addresses and size to be copied.
 */
struct copy_virtual_memory_t {
    _In_ uint64_t src_cr3; ///< Source CR3 value
    _In_ uint64_t dst_cr3; ///< Destination CR3 value

    _In_ void* src; ///< Source memory address
    _In_ void* dst; ///< Destination memory address

    _In_ uint64_t size; ///< Size of the memory to copy
};

/**
 * @brief Structure to get the CR3 of a process.
 *
 * This structure is used to request the CR3 of a specific process identified by its PID.
 */
struct get_cr3_t {
    _In_ uint64_t pid; ///< Process ID

    _Out_ uint64_t cr3; ///< CR3 of the process
};

/**
 * @brief Structure to get the base address of a module in a process.
 *
 * This structure is used to request the base address of a module given its name and the PID of the process.
 */
struct get_module_base_t {
    _In_ char module_name[MAX_PATH]; ///< Module name
    _In_ uint64_t pid; ///< Process ID

    _Out_ uint64_t module_base; ///< Base address of the module
};

/**
 * @brief Structure to get the size of a module in a process.
 *
 * This structure is used to request the size of a module in a specific process.
 */
struct get_module_size_t {
    _In_ char module_name[MAX_PATH]; ///< Module name
    _In_ uint64_t pid; ///< Process ID

    _Out_ uint64_t module_size; ///< Size of the module
};

/**
 * @brief Structure to get the PID of a process by its name.
 *
 * This structure is used to request the PID of a process given its name.
 */
struct get_pid_by_name_t {
    _In_ char name[MAX_PATH]; ///< Name of the process

    _Out_ uint64_t pid; ///< Process ID
};

/**
 * @brief Structure to get the count of entries in the loader data table for a process.
 *
 * This structure is used to request the number of entries in the loader data table for a specific process.
 */
struct get_ldr_data_table_entry_count_t {
    _In_ uint64_t pid; ///< Process ID

    _Out_ uint64_t count; ///< Number of entries in the loader data table
};

/**
 * @brief Structure to store module information.
 *
 * This structure holds the module's name, base address, and size.
 */
struct module_info_t {
    _In_ char name[MAX_PATH]; ///< Module name
    _In_ uint64_t base; ///< Base address of the module
    _In_ uint64_t size; ///< Size of the module
};

/**
 * @brief Structure to request data table entry information for a process.
 *
 * This structure is used to request information about the entries in the data table for a specific process.
 */
struct cmd_get_data_table_entry_info_t {
    _In_ uint64_t pid; ///< Process ID
    _In_ module_info_t* info_array; ///< Array to hold module info
};

/**
 * @brief Maximum number of messages allowed for logging.
 */
#define MAX_MESSAGES 512

 /**
  * @brief Maximum size of each message in the log.
  */
#define MAX_MESSAGE_SIZE 256

  /**
   * @brief Structure for a log entry.
   *
   * This structure represents a log entry containing a boolean flag indicating presence
   * and the actual payload of the log entry.
   */
struct log_entry_t {
    bool present; ///< Indicates whether the log entry is present
    char payload[MAX_MESSAGE_SIZE]; ///< Log entry content
};

/**
 * @brief Structure for command output logs.
 *
 * This structure holds the count of log entries and an array of log entries.
 */
struct cmd_output_logs_t {
    _In_ uint32_t count; ///< Number of log entries
    _In_ log_entry_t* log_array; ///< Array of log entries
};

/**
 * @brief Enum representing various command types.
 *
 * This enum defines the different types of commands that can be issued.
 */
enum call_types_t : uint32_t {
    cmd_get_pid_by_name, ///< Get the PID of a process by its name
    cmd_get_cr3, ///< Get the CR3 of a process

    cmd_get_module_base, ///< Get the base address of a module in a process
    cmd_get_module_size, ///< Get the size of a module in a process
    cmd_get_ldr_data_table_entry_count, ///< Get the number of entries in the loader data table for a process
    cmd_get_data_table_entry_info, ///< Get data table entry information for a process

    cmd_copy_virtual_memory, ///< Command to copy virtual memory

    cmd_output_logs, ///< Command to output logs

    cmd_remove_from_system_page_tables, ///< Command to remove a driver from system page tables
    cmd_unload_driver, ///< Command to unload a driver
    cmd_ping_driver, ///< Command to ping a driver
};

/**
 * @brief Structure to represent a command.
 *
 * This structure is used to represent a command with its status, type, and additional data.
 */
struct command_t {
    bool status; ///< Status of the command (success/failure)
    call_types_t call_type; ///< Type of the command
    void* sub_command_ptr; ///< Pointer to additional data for the sub-command
};

#pragma optimize("", on) ///< Restore original optimization settings
