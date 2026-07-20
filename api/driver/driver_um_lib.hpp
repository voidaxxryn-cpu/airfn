#pragma once
#include "driver_includes.hpp"
#include "driver_shared.hpp"

// Constants
/// Stack identifier used for handling specific memory stack operations.
constexpr uint64_t stack_id = 0xdeed;

/// Signature representing an NMI (Non-Maskable Interrupt) occurrence.
constexpr uint64_t nmi_occured = 0x01010101;

/// A unique signature identifier for the caller (used for validation).
constexpr uint32_t caller_signature = 0x6969;

/// Win11 23H2+ build number threshold (matches the driver-side check).
constexpr uint32_t win11_23h2_build = 22631;

/// Function pointer type for the `NtUserGetCPD` function from the `win32u.dll` library (Win10/Win11 22H2).
typedef __int64(__fastcall* NtUserGetCPD_type)(uint64_t hwnd, uint32_t flags, ULONG_PTR dw_data);
extern "C" NtUserGetCPD_type NtUserGetCPD;

/// Function pointer type for the Win11 23H2+ hooked function (2-arg signature).
typedef __int64(__fastcall* Win11HookFunc_type)(uint64_t a1, uint64_t a2);
extern "C" Win11HookFunc_type Win11HookFunc;

/// External ASM functions for handling NMI interrupts.
/// These functions are invoked in assembly code for specific NMI-related operations.
extern "C" void asm_nmi_wrapper(void);
extern "C" void asm_nmi_restoring(void);
extern "C" __int64 __fastcall asm_call_driver(uint64_t hwnd, uint32_t flags, ULONG_PTR dw_data);
extern "C" __int64 __fastcall asm_call_driver_win11(uint64_t a1, uint64_t a2, uint64_t nmi_restoring_addr);

namespace rose {
    /// Flag indicating whether the Roseware library has been initialized.
    inline bool inited = false;

    /// Flag indicating whether the Win11 23H2+ hook path is active.
    inline bool use_win11_hook = false;

    /**
     * @brief Sends a request command to the driver.
     *
     * This function sends a command to the driver and waits for a response.
     *
     * @param cmd Pointer to the command data to be sent.
     * @return The result of the request, typically an integer or pointer.
     */
    __int64 send_request(void* cmd);

    /**
     * @brief Copies virtual memory between two processes.
     *
     * This function uses CR3 registers to copy memory from one process to another.
     *
     * @param src_cr3 The CR3 value of the source process.
     * @param dst_cr3 The CR3 value of the destination process.
     * @param src Pointer to the source memory location.
     * @param dst Pointer to the destination memory location.
     * @param size The size of memory to copy.
     * @return true if the memory copy was successful, false otherwise.
     */
    bool copy_virtual_memory(uint64_t src_cr3, uint64_t dst_cr3, void* src, void* dst, uint64_t size);

    /**
     * @brief Retrieves the CR3 value for a given process.
     *
     * The CR3 register holds the physical address of the page table directory for the process.
     *
     * @param pid The process ID of the target process.
     * @return The CR3 value of the target process, or 0 if an error occurs.
     */
    uint64_t get_cr3(uint64_t pid);

    /**
     * @brief Gets the base address of a module in a target process.
     *
     * This function retrieves the base address of a loaded module within a target process.
     *
     * @param module_name The name of the module to search for.
     * @param pid The process ID of the target process.
     * @return The base address of the module, or 0 if not found.
     */
    uint64_t get_module_base(const char* module_name, uint64_t pid);

    /**
     * @brief Gets the size of a module in a target process.
     *
     * This function retrieves the size of a loaded module within a target process.
     *
     * @param module_name The name of the module to search for.
     * @param pid The process ID of the target process.
     * @return The size of the module, or 0 if not found.
     */
    uint64_t get_module_size(const char* module_name, uint64_t pid);

    /**
     * @brief Retrieves the process ID (PID) of a process by its name.
     *
     * This function finds the PID of a process based on its executable name.
     *
     * @param name The name of the process to search for.
     * @return The PID of the process, or 0 if the process could not be found.
     */
    uint64_t get_pid_by_name(const char* name);

    /**
     * @brief Gets the number of loaded modules in a target process.
     *
     * This function retrieves the number of modules that are loaded in the target process.
     *
     * @param pid The process ID of the target process.
     * @return The number of modules loaded, or 0 if an error occurs.
     */
    uint64_t get_ldr_data_table_entry_count(uint64_t pid);

    /**
     * @brief Retrieves detailed information about the modules loaded in a target process.
     *
     * This function fills the provided array with information about each module in the target process.
     *
     * @param pid The process ID of the target process.
     * @param info_array Pointer to an array where module information will be stored.
     * @return true if the module data is successfully retrieved, false otherwise.
     */
    bool get_data_table_entry_info(uint64_t pid, module_info_t* info_array);

    /**
     * @brief Hides the driver from detection.
     *
     * This function attempts to hide the driver to avoid detection by the system.
     * It should be called during the initialization phase.
     *
     * @return true if the driver was successfully hidden, false otherwise.
     */
    bool hide_driver(void);

    /**
     * @brief Unloads the driver from memory.
     *
     * This function unloads the driver, effectively terminating its operation.
     *
     * @return true if the driver was successfully unloaded, false otherwise.
     */
    bool unload_driver(void);

    /**
     * @brief Pings the driver to check its status.
     *
     * This function verifies whether the driver is loaded and functioning correctly.
     *
     * @return true if the driver is responsive, false otherwise.
     */
    bool ping_driver(void);

    /**
     * @brief Flushes all logs accumulated during driver operations.
     *
     * This function flushes any logs that have been generated during the driver's operations.
     * Typically used for debugging purposes.
     */
    void flush_logs(void);

    /**
     * @brief Initializes the Roseware library.
     *
     * This function performs initialization of the Roseware library, which includes loading necessary
     * DLLs and preparing the driver for interaction. Detects Win11 23H2+ and uses the appropriate
     * hook calling convention.
     *
     * @return true if the library is successfully initialized, false otherwise.
     */
    inline bool init_roseware_lib() {
        if (inited)
            return true;

        // Load user32.dll to ensure compatibility with NtUser functions
        if (!LoadLibraryW(L"user32.dll")) {
            LOG_INFO("Failed to load user32.dll");
            return false;
        }

        // Load win32u.dll and resolve the appropriate hook function
        HMODULE win32u = LoadLibraryW(L"win32u.dll");
        if (!win32u) {
            LOG_INFO("Failed to get win32u.dll handle");
            return false;
        }

        // Detect Win11 23H2+ to match the driver-side hook path
        OSVERSIONINFOW os_info = { 0 };
        os_info.dwOSVersionInfoSize = sizeof(os_info);
        typedef LONG(WINAPI* RtlGetVersion_t)(PRTL_OSVERSIONINFOW);
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        RtlGetVersion_t pRtlGetVersion = 0;
        if (ntdll) {
            pRtlGetVersion = (RtlGetVersion_t)GetProcAddress(ntdll, "RtlGetVersion");
        }
        if (pRtlGetVersion) {
            pRtlGetVersion((PRTL_OSVERSIONINFOW)&os_info);
        }

        use_win11_hook = (os_info.dwBuildNumber >= win11_23h2_build);

        if (use_win11_hook) {
            // Win11 23H2+: resolve the function that triggers the gSessionGlobalSlots table entry.
            // The hooked entry at table[0xA00/8] corresponds to NtUserGetCPD on Win11 23H2+
            // but is dispatched through the session global slots mechanism with a 2-arg signature.
            // We still call NtUserGetCPD from usermode — the syscall routing reaches the hooked entry.
            uint64_t handler_address = (uint64_t)GetProcAddress(win32u, "NtUserGetCPD");
            if (!handler_address) {
                LOG_INFO("Failed to resolve NtUserGetCPD for Win11 path");
                return false;
            }
            Win11HookFunc = (Win11HookFunc_type)handler_address;
            NtUserGetCPD = nullptr;
            LOG_INFO("Win11 23H2+ detected (build %d), using 2-arg hook path", os_info.dwBuildNumber);
        }
        else {
            // Win10 / Win11 22H2: use the classic NtUserGetCPD 3-arg path
            uint64_t handler_address = (uint64_t)GetProcAddress(win32u, "NtUserGetCPD");
            NtUserGetCPD = (NtUserGetCPD_type)handler_address;
            Win11HookFunc = nullptr;
        }

        inited = true;

        // Ensure the driver is loaded and can be pinged
        if (!ping_driver()) {
            LOG_INFO("Driver is not loaded");
            return false;
        }

        // Hide the driver for stealth purposes
        if (!hide_driver()) {
            LOG_INFO("Failed to hide driver");
            return false;
        }

        return true;
    }

    /**
     * @brief Checks if the Roseware library has been initialized.
     *
     * This function checks if the library has been properly initialized.
     *
     * @return true if the library is initialized, false otherwise.
     */
    inline bool is_lib_inited(void) {
        return inited;
    }

    /**
     * @brief Checks if a valid hook function pointer is available.
     *
     * @return true if either the Win10 or Win11 hook function is resolved.
     */
    inline bool is_hook_ready(void) {
        if (use_win11_hook)
            return Win11HookFunc != nullptr;
        return NtUserGetCPD != nullptr;
    }
};

// Structure representing a CPU trap frame.
#pragma pack(push, 1)
struct trap_frame_t {
    uint64_t r15; ///< Value of the R15 register.
    uint64_t r14; ///< Value of the R14 register.
    uint64_t r13; ///< Value of the R13 register.
    uint64_t r12; ///< Value of the R12 register.
    uint64_t r11; ///< Value of the R11 register.
    uint64_t r10; ///< Value of the R10 register.
    uint64_t r9;  ///< Value of the R9 register.
    uint64_t r8;  ///< Value of the R8 register.
    uint64_t rbp; ///< Value of the RBP register.
    uint64_t rdi; ///< Value of the RDI register.
    uint64_t rsi; ///< Value of the RSI register.
    uint64_t rdx; ///< Value of the RDX register.
    uint64_t rcx; ///< Value of the RCX register.
    uint64_t rbx; ///< Value of the RBX register.
    uint64_t rax; ///< Value of the RAX register.
    uint64_t rsp; ///< Value of the RSP register.
};
#pragma pack(pop)
