#include "driver_um_lib.hpp"
#include <winnt.h>
#include <winternl.h>

extern "C" NtUserGetCPD_type NtUserGetCPD = 0;
extern "C" Win11HookFunc_type Win11HookFunc = 0;

// Restores from a nmi
/**
 * @brief Restores from a Non-Maskable Interrupt (NMI) and resets the stack pointer.
 *
 * This function searches the stack for a specific identifier (stack_id) and restores the
 * state of the trap frame, including setting the `rax` register to signal that the NMI occurred.
 * It then adjusts the stack pointer to point to the return address.
 *
 * @param trap_frame Pointer to the trap frame structure that holds the CPU register state.
 */
extern "C" void nmi_restoring(trap_frame_t* trap_frame) {
    uint64_t* stack_ptr = (uint64_t*)trap_frame->rsp;

    while (true) {
        if (*stack_ptr != stack_id) {
            stack_ptr++; // Move up the stack
            continue;
        }

        trap_frame->rax = nmi_occured;

        // Restore rsp
        trap_frame->rsp = (uint64_t)stack_ptr + 0x8; // Point top of rsp to a ret address

        // Return to the send request
        return;
    }
}

namespace rose {

    /**
     * @brief Sends a command request to the driver and handles NMI recovery.
     *
     * This function sends a command to the driver using the appropriate calling convention.
     * On Win10/Win11 22H2, it uses `asm_call_driver` (3-arg NtUserGetCPD path).
     * On Win11 23H2+, it uses `asm_call_driver_win11` (2-arg gSessionGlobalSlots path).
     * If an NMI occurs, the function will recursively call itself to handle the interrupt.
     *
     * @param cmd Pointer to the command data to be sent to the driver.
     * @return The result of the driver command, or -1 if an error occurs.
     */
    __int64 send_request(void* cmd) {
        __int64 ret;

        if (use_win11_hook) {
            ret = asm_call_driver_win11((uint64_t)cmd, (uint64_t)caller_signature, (uint64_t)asm_nmi_restoring);
        }
        else {
            ret = asm_call_driver((uint64_t)cmd, caller_signature, (uint64_t)asm_nmi_restoring);
        }

        if (ret == nmi_occured) {
            return send_request(cmd);
        }

        return ret;
    }

    /**
     * @brief Copies virtual memory between two different processes.
     *
     * This function allows copying memory from one process (specified by CR3) to another.
     *
     * @param src_cr3 The CR3 value of the source process.
     * @param dst_cr3 The CR3 value of the destination process.
     * @param src Pointer to the source memory location.
     * @param dst Pointer to the destination memory location.
     * @param size Size of memory to copy.
     * @return true if the memory copy was successful, false otherwise.
     */
    bool copy_virtual_memory(uint64_t src_cr3, uint64_t dst_cr3, void* src, void* dst, uint64_t size) {
        if (!inited || !is_hook_ready())
            return false;

        copy_virtual_memory_t copy_mem_cmd = { 0 };
        copy_mem_cmd.src_cr3 = src_cr3;
        copy_mem_cmd.dst_cr3 = dst_cr3;
        copy_mem_cmd.src = src;
        copy_mem_cmd.dst = dst;
        copy_mem_cmd.size = size;

        command_t cmd = { 0 };
        cmd.call_type = cmd_copy_virtual_memory;
        cmd.sub_command_ptr = &copy_mem_cmd;

        send_request(&cmd);

        return cmd.status;
    }

    /**
     * @brief Retrieves the CR3 value for a specified process.
     *
     * The CR3 value corresponds to the page table base for the target process.
     *
     * @param pid Process ID of the target process.
     * @return The CR3 value of the process, or 0 if an error occurs.
     */
    uint64_t get_cr3(uint64_t pid) {
        if (!inited || !is_hook_ready())
            return 0;

        get_cr3_t get_cr3_cmd = { 0 };
        get_cr3_cmd.pid = pid;

        command_t cmd = { 0 };
        cmd.call_type = cmd_get_cr3;
        cmd.sub_command_ptr = &get_cr3_cmd;

        send_request(&cmd);

        return get_cr3_cmd.cr3;
    }

    /**
     * @brief Gets the base address of a specified module within a target process.
     *
     * This function searches for the module by name and returns its base address.
     *
     * @param module_name The name of the module.
     * @param pid The process ID of the target process.
     * @return The base address of the module, or 0 if the module is not found.
     */
    uint64_t get_module_base(const char* module_name, uint64_t pid) {
        if (!inited || !is_hook_ready())
            return 0;

        get_module_base_t get_module_base_cmd = { 0 };
        strncpy(get_module_base_cmd.module_name, module_name, MAX_PATH - 1);
        get_module_base_cmd.pid = pid;

        command_t cmd = { 0 };
        cmd.call_type = cmd_get_module_base;
        cmd.sub_command_ptr = &get_module_base_cmd;

        send_request(&cmd);

        return get_module_base_cmd.module_base;
    }

    /**
     * @brief Gets the size of a specified module in a target process.
     *
     * This function retrieves the size of a loaded module within the specified process.
     *
     * @param module_name The name of the module.
     * @param pid The process ID of the target process.
     * @return The size of the module, or 0 if the module is not found.
     */
    uint64_t get_module_size(const char* module_name, uint64_t pid) {
        if (!inited || !is_hook_ready())
            return 0;

        get_module_size_t get_module_size_cmd = { 0 };
        strncpy(get_module_size_cmd.module_name, module_name, MAX_PATH - 1);
        get_module_size_cmd.pid = pid;

        command_t cmd = { 0 };
        cmd.call_type = cmd_get_module_size;
        cmd.sub_command_ptr = &get_module_size_cmd;

        send_request(&cmd);

        return get_module_size_cmd.module_size;
    }

    /**
     * @brief Retrieves the process ID (PID) of a process by its name.
     *
     * This function searches for a process by its name and returns its PID.
     *
     * @param name The name of the target process.
     * @return The PID of the process, or 0 if not found.
     */
    uint64_t get_pid_by_name(const char* name) {
        if (!inited || !is_hook_ready())
            return 0;

        get_pid_by_name_t get_pid_by_name_cmd = { 0 };
        strncpy(get_pid_by_name_cmd.name, name, MAX_PATH - 1);

        command_t cmd = { 0 };
        cmd.call_type = cmd_get_pid_by_name;
        cmd.sub_command_ptr = &get_pid_by_name_cmd;

        send_request(&cmd);

        return get_pid_by_name_cmd.pid;
    }

    /**
     * @brief Retrieves the count of loaded modules in a target process.
     *
     * This function returns the number of loaded modules in the specified process.
     *
     * @param pid The process ID of the target process.
     * @return The number of loaded modules, or 0 if an error occurs.
     */
    uint64_t get_ldr_data_table_entry_count(uint64_t pid) {
        if (!inited || !is_hook_ready())
            return 0;

        get_ldr_data_table_entry_count_t get_ldr_data_table_entry = { 0 };
        get_ldr_data_table_entry.pid = pid;

        command_t cmd = { 0 };
        cmd.call_type = cmd_get_ldr_data_table_entry_count;
        cmd.sub_command_ptr = &get_ldr_data_table_entry;

        send_request(&cmd);

        return get_ldr_data_table_entry.count;
    }

    /**
     * @brief Retrieves detailed information about the modules loaded in a target process.
     *
     * This function populates the provided array with information about each loaded module.
     *
     * @param pid The process ID of the target process.
     * @param info_array Pointer to an array where module information will be stored.
     * @return true if the data was retrieved successfully, false otherwise.
     */
    bool get_data_table_entry_info(uint64_t pid, module_info_t* info_array) {
        if (!inited || !is_hook_ready())
            return false;

        cmd_get_data_table_entry_info_t get_module_at_index = { 0 };
        get_module_at_index.pid = pid;
        get_module_at_index.info_array = info_array;

        command_t cmd = { 0 };
        cmd.call_type = cmd_get_data_table_entry_info;
        cmd.sub_command_ptr = &get_module_at_index;

        send_request(&cmd);

        return cmd.status;
    }

    /**
     * @brief Hides the driver from the system by removing it from page tables.
     *
     * This function attempts to hide the driver, preventing detection by the system.
     *
     * @return true if the driver was successfully hidden, false otherwise.
     */
    bool hide_driver(void) {
        if (!inited || !is_hook_ready())
            return false;

        command_t cmd = { 0 };
        cmd.call_type = cmd_remove_from_system_page_tables;

        send_request(&cmd);

        return cmd.status;
    }

    /**
     * @brief Unloads the driver from memory.
     *
     * This function unloads the driver from memory, effectively terminating its operation.
     *
     * @return true if the driver was successfully unloaded, false otherwise.
     */
    bool unload_driver(void) {
        if (!inited || !is_hook_ready()) {
            if (!rose::init_roseware_lib())
                return false;
        }

        command_t cmd = { 0 };
        cmd.call_type = cmd_unload_driver;

        send_request(&cmd);

        return cmd.status;
    }

    /**
     * @brief Pings the driver to check its status.
     *
     * This function checks whether the driver is responsive.
     *
     * @return true if the driver is responsive, false otherwise.
     */
    bool ping_driver(void) {
        if (!inited || !is_hook_ready())
            return false;

        command_t cmd = { 0 };
        cmd.call_type = cmd_ping_driver;

        send_request(&cmd);

        return cmd.status;
    }

    /**
     * @brief Flushes logs generated by the driver.
     *
     * This function retrieves and prints the logs generated during driver operations.
     */
    void flush_logs(void) {
        if (!inited || !is_hook_ready())
            return;

        log_entry_t* log_array = new log_entry_t[512];
        memset(log_array, 0, sizeof(log_entry_t) * 512);

        cmd_output_logs_t sub_cmd;
        sub_cmd.count = 512;
        sub_cmd.log_array = log_array;

        command_t cmd = { 0 };
        cmd.call_type = cmd_output_logs;
        cmd.sub_command_ptr = &sub_cmd;

        send_request(&cmd);
        if (!cmd.status) {
            LOG_INFO("Failed flushing logs");
            return;
        }

        if (!log_array[0].present) {
            delete[] log_array;
            return;
        }

        LOG_NEW_LINE("");
        LOG_INFO("Root Log:");
        for (uint32_t i = 0; i < 512; i++) {
            if (!log_array[i].present)
                continue;

            LOG_INFO("Root: %s", log_array[i].payload);
        }
        LOG_NEW_LINE("");

        delete[] log_array;
    }
};
