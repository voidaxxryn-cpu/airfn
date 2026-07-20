#pragma once
#pragma optimize("", off)
// Designed to be a standalone, includable .hpp, thus we need to make our own definitions etc.

/**
 * @file driver_shared.hpp
 * @brief Shared headers and structures used for communication between user mode and driver.
 */

 /*
     Typedefs and Definitions
 */

 /**
  * @brief Defines the maximum path length for file paths and other strings.
  */
#ifndef MAX_PATH
#define MAX_PATH 260
#endif // !MAX_PATH

  /**
   * @brief Typedef for unsigned 8-bit integer.
   */
using uint8_t = unsigned char;

/**
 * @brief Typedef for unsigned 16-bit integer.
 */
using uint16_t = unsigned short;

/**
 * @brief Typedef for unsigned 32-bit integer.
 */
using uint32_t = unsigned int;

/**
 * @brief Typedef for unsigned 64-bit integer.
 */
using uint64_t = unsigned long long;

/*
    Communication structs
*/

/**
 * @brief Structure for copying virtual memory between two different processes.
 */
struct copy_virtual_memory_t {
    _In_ uint64_t src_cr3;  ///< The CR3 value of the source process.
    _In_ uint64_t dst_cr3;  ///< The CR3 value of the destination process.
    _In_ void* src;         ///< Pointer to the source memory location.
    _In_ void* dst;         ///< Pointer to the destination memory location.
    _In_ uint64_t size;     ///< The size of memory to copy.
};

/**
 * @brief Structure for retrieving the CR3 value for a specified process.
 */
struct get_cr3_t {
    _In_ uint64_t pid;      ///< The process ID of the target process.
    _Out_ uint64_t cr3;     ///< The CR3 value for the process.
};

/**
 * @brief Structure for retrieving the base address of a specified module.
 */
struct get_module_base_t {
    _In_ char module_name[MAX_PATH]; ///< The name of the module.
    _In_ uint64_t pid;               ///< The process ID of the target process.
    _Out_ uint64_t module_base;      ///< The base address of the module.
};

/**
 * @brief Structure for retrieving the size of a specified module.
 */
struct get_module_size_t {
    _In_ char module_name[MAX_PATH]; ///< The name of the module.
    _In_ uint64_t pid;               ///< The process ID of the target process.
    _Out_ uint64_t module_size;      ///< The size of the module.
};

/**
 * @brief Structure for retrieving the process ID by process name.
 */
struct get_pid_by_name_t {
    _In_ char name[MAX_PATH];  ///< The name of the process.
    _Out_ uint64_t pid;        ///< The process ID of the target process.
};

/**
 * @brief Structure for retrieving the count of loaded modules in a target process.
 */
struct get_ldr_data_table_entry_count_t {
    _In_ uint64_t pid;         ///< The process ID of the target process.
    _Out_ uint64_t count;      ///< The number of loaded modules in the process.
};

/**
 * @brief Structure for storing module information.
 */
struct module_info_t {
    _In_ char name[MAX_PATH]; ///< The name of the module.
    _In_ uint64_t base;       ///< The base address of the module.
    _In_ uint64_t size;       ///< The size of the module.
};

/**
 * @brief Structure for retrieving module information about loaded modules.
 */
struct cmd_get_data_table_entry_info_t {
    _In_ uint64_t pid;              ///< The process ID of the target process.
    _In_ module_info_t* info_array; ///< Array of module information.
};

/**
 * @brief Maximum number of messages that can be stored in the log.
 */
#define MAX_MESSAGES 512

 /**
  * @brief Maximum size of each log message.
  */
#define MAX_MESSAGE_SIZE 256

  /**
   * @brief Structure for storing a log entry.
   */
struct log_entry_t {
    bool present;                ///< Indicates if the log entry is present.
    char payload[MAX_MESSAGE_SIZE]; ///< The log message content.
};

/**
 * @brief Structure for retrieving logs from the driver.
 */
struct cmd_output_logs_t {
    _In_ uint32_t count;        ///< The number of log entries to retrieve.
    _In_ log_entry_t* log_array; ///< The array to store log entries.
};

/**
 * @brief Enum representing the different types of commands that can be sent to the driver.
 */
enum call_types_t : uint32_t {
    cmd_get_pid_by_name,                ///< Get process ID by process name.
    cmd_get_cr3,                         ///< Get CR3 value for a process.
    cmd_get_module_base,                 ///< Get the base address of a module.
    cmd_get_module_size,                 ///< Get the size of a module.
    cmd_get_ldr_data_table_entry_count,  ///< Get the number of loaded modules in a process.
    cmd_get_data_table_entry_info,       ///< Get information about loaded modules.
    cmd_copy_virtual_memory,             ///< Copy virtual memory between processes.
    cmd_output_logs,                     ///< Retrieve logs from the driver.
    cmd_remove_from_system_page_tables,  ///< Remove the driver from the system page tables.
    cmd_unload_driver,                   ///< Unload the driver.
    cmd_ping_driver,                     ///< Ping the driver to check its status.
};

/**
 * @brief Structure representing a command to be sent to the driver.
 */
struct command_t {
    bool status;               ///< Status of the command (success or failure).
    call_types_t call_type;    ///< The type of command being sent.
    void* sub_command_ptr;     ///< Pointer to the sub-command data.
};

#pragma optimize("", on)
