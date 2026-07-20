#include "project_includes.hpp"
#include "windows_structs.hpp"
#include <ntimage.h>

extern "C" NTKERNELAPI ULONG PsGetProcessSessionId(_In_ PEPROCESS Process);

namespace utility {

    /**
     * @brief Retrieves the base address of a loaded driver module.
     *
     * This function searches the loaded module list for a module with a matching driver name
     * and returns its base address if found.
     *
     * @param driver_name The name of the driver module to search for.
     * @param driver_base A reference to the variable that will receive the driver base address.
     * @return Returns `status_success` if the driver was found, otherwise `status_failure`.
     */
    project_status get_driver_module_base(const wchar_t* driver_name, void*& driver_base) {
        PLIST_ENTRY head = PsLoadedModuleList;
        PLIST_ENTRY curr = head->Flink;

        // Traverse the loaded modules list
        while (curr != head) {
            LDR_DATA_TABLE_ENTRY* curr_mod = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            // Compare the loaded module name with the target driver name
            if (_wcsicmp(curr_mod->BaseDllName.Buffer, driver_name) == 0) {
                driver_base = curr_mod->DllBase;
                return status_success;
            }

            curr = curr->Flink;
        }

        return status_failure;  // Return failure if the module was not found
    }

    /**
     * @brief Retrieves the EPROCESS structure of a process by name.
     *
     * This function searches through the active processes and compares their image names.
     * If a process with the specified name is found and it has active threads, the EPROCESS
     * structure is returned.
     *
     * @param process_name The name of the process to search for.
     * @param pe_proc A reference to the EPROCESS structure of the process, if found.
     * @return Returns `status_success` if the process was found, otherwise `status_failure`.
     */
    project_status get_eprocess(const char* process_name, PEPROCESS& pe_proc) {
        if (!process_name || !process_name[0]) {
            return status_invalid_parameter;
        }

        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;
        char image_name[IMAGE_NAME_LENGTH + 1];

        do {
            memset(image_name, 0, sizeof(image_name));

            const char* proc_image_name = (const char*)PsGetProcessImageFileName(curr_entry);
            if (proc_image_name && proc_image_name[0]) {
                strncpy(image_name, proc_image_name, IMAGE_NAME_LENGTH);
                image_name[IMAGE_NAME_LENGTH] = '\0';
            }
            else {
                memcpy(image_name, (void*)((uintptr_t)curr_entry + IMAGE_NAME_OFFSET), IMAGE_NAME_LENGTH);
                image_name[IMAGE_NAME_LENGTH] = '\0';
            }

            bool exact_match = (_stricmp(image_name, process_name) == 0);
            bool prefix_match = (_strnicmp(process_name, image_name, IMAGE_NAME_LENGTH) == 0);
            if (exact_match || prefix_match) {
                uint32_t active_threads;
                memcpy(&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

                if (active_threads > 0) {
                    pe_proc = curr_entry;
                    return status_success;
                }
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);

        } while (curr_entry != sys_process);

        return status_failure;  // Return failure if process is not found
    }

    project_status get_eprocess_in_session(const char* process_name, ULONG session_id, PEPROCESS& pe_proc) {
        if (!process_name || !process_name[0]) {
            return status_invalid_parameter;
        }

        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;
        char image_name[IMAGE_NAME_LENGTH + 1];

        do {
            memset(image_name, 0, sizeof(image_name));

            const char* proc_image_name = (const char*)PsGetProcessImageFileName(curr_entry);
            if (proc_image_name && proc_image_name[0]) {
                strncpy(image_name, proc_image_name, IMAGE_NAME_LENGTH);
                image_name[IMAGE_NAME_LENGTH] = '\0';
            }
            else {
                memcpy(image_name, (void*)((uintptr_t)curr_entry + IMAGE_NAME_OFFSET), IMAGE_NAME_LENGTH);
                image_name[IMAGE_NAME_LENGTH] = '\0';
            }

            bool exact_match = (_stricmp(image_name, process_name) == 0);
            bool prefix_match = (_strnicmp(process_name, image_name, IMAGE_NAME_LENGTH) == 0);
            if (exact_match || prefix_match) {
                uint32_t active_threads;
                memcpy(&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

                if (active_threads > 0 && PsGetProcessSessionId(curr_entry) == session_id) {
                    pe_proc = curr_entry;
                    return status_success;
                }
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);

        } while (curr_entry != sys_process);

        return status_failure;
    }

    /**
     * @brief Finds a byte pattern within a specified memory range.
     *
     * This function searches through a specified memory region and attempts to find a given byte pattern.
     * A wildcard can be used in the pattern to match any byte in that position.
     *
     * @param region_base The base address of the memory region to search.
     * @param region_size The size of the memory region to search.
     * @param pattern The byte pattern to search for.
     * @param pattern_size The size of the byte pattern.
     * @param wildcard A character that represents a wildcard, which can match any byte in the pattern.
     * @return Returns the address where the pattern was found, or 0 if not found.
     */
    uintptr_t find_pattern_in_range(uintptr_t region_base, size_t region_size, const char* pattern, size_t pattern_size, char wildcard) {
        char* region_end = (char*)region_base + region_size - pattern_size + 1;

        for (char* byte = (char*)region_base; byte < region_end; ++byte) {
            if (*byte == *pattern || *pattern == wildcard) {
                bool found = true;
                for (size_t i = 1; i < pattern_size; ++i) {
                    if (pattern[i] != byte[i] && pattern[i] != wildcard) {
                        found = false;
                        break;
                    }
                }
                if (found) {
                    return (uintptr_t)byte;
                }
            }
        }

        return 0;  // Return 0 if the pattern was not found
    }

    /**
     * @brief Searches for a byte pattern in a section of a module.
     *
     * This function locates a specified section of a module and searches for a byte pattern within that section.
     * A wildcard can be used in the pattern to match any byte.
     *
     * @param module_handle A handle to the module to search within.
     * @param section_name The name of the section to search.
     * @param pattern The byte pattern to search for.
     * @param pattern_size The size of the byte pattern.
     * @param wildcard A character that represents a wildcard, which can match any byte in the pattern.
     * @return Returns the address where the pattern was found in the section, or 0 if not found.
     */
    uintptr_t search_pattern_in_section(void* module_handle, const char* section_name, const char* pattern, uint64_t pattern_size, char wildcard) {
        IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_handle;
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;  // Return 0 if the DOS signature is invalid
        }

        IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)((uintptr_t)module_handle + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
            return 0;  // Return 0 if the NT headers signature is invalid
        }

        IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((uintptr_t)nt_headers + sizeof(IMAGE_NT_HEADERS64));

        for (uint32_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
            // Ensure section is executable and not discardable
            if (!(sections[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
                !(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                (sections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) {
                continue;
            }

            if (strncmp((const char*)sections[i].Name, section_name, IMAGE_SIZEOF_SHORT_NAME) == 0) {
                uintptr_t section_start = (uintptr_t)module_handle + sections[i].VirtualAddress;
                uint32_t section_size = sections[i].Misc.VirtualSize;

                uintptr_t result = find_pattern_in_range(section_start, section_size, pattern, pattern_size, wildcard);
                return result;
            }
        }

        return 0;  // Return 0 if no matching section or pattern is found
    }

    /**
     * @brief Checks if a data pointer is within a valid region of loaded modules.
     *
     * This function checks whether a given data pointer lies within the address range of any loaded module.
     *
     * @param data_ptr The data pointer to check.
     * @return Returns `status_success` if the data pointer is valid, otherwise `status_data_ptr_invalid`.
     */
    project_status is_data_ptr_in_valid_region(uint64_t data_ptr) {
        PLIST_ENTRY head = PsLoadedModuleList;
        PLIST_ENTRY curr = head->Flink;

        // Traverse the loaded modules list to check if the data pointer is in a valid range
        while (curr != head) {
            LDR_DATA_TABLE_ENTRY* curr_mod = CONTAINING_RECORD(curr, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            uint64_t driver_base = (uint64_t)curr_mod->DllBase;
            uint64_t driver_end = driver_base + curr_mod->SizeOfImage;

            // If the data pointer is within the boundaries of a loaded module, it's considered valid
            if (data_ptr >= driver_base && data_ptr < driver_end) {
                return status_success;
            }

            curr = curr->Flink;
        }

        return status_data_ptr_invalid;  // Return invalid status if the pointer is not valid
    }

    /**
     * @brief Retrieves the CR3 value for a specific process.
     *
     * This function searches for a process by its PID, and if the process has active threads,
     * it retrieves the CR3 register value, which points to the page directory.
     *
     * @param target_pid The PID of the target process.
     * @return Returns the CR3 value for the specified process, or 0 if not found.
     */
    uint64_t get_cr3(uint64_t target_pid) {
        PEPROCESS sys_process = PsInitialSystemProcess;
        PEPROCESS curr_entry = sys_process;

        do {
            uint64_t curr_pid;

            memcpy(&curr_pid, (void*)((uintptr_t)curr_entry + PID_OFFSET), sizeof(curr_pid));

            // Check whether we found our process
            if (target_pid == curr_pid) {

                uint32_t active_threads;

                memcpy((void*)&active_threads, (void*)((uintptr_t)curr_entry + ACTIVE_THREADS), sizeof(active_threads));

                if (active_threads || target_pid == SYSTEM_PID) {
                    uint64_t cr3;

                    memcpy(&cr3, (void*)((uintptr_t)curr_entry + DIRECTORY_TABLE_BASE_OFFSET), sizeof(cr3));

                    return cr3;
                }
            }

            PLIST_ENTRY list = (PLIST_ENTRY)((uintptr_t)(curr_entry)+FLINK_OFFSET);
            curr_entry = (PEPROCESS)((uintptr_t)list->Flink - FLINK_OFFSET);
        } while (curr_entry != sys_process);

        return 0;  // Return 0 if CR3 could not be found
    }

    project_status map_module_from_known_dll(const wchar_t* dll_name, void*& module_base) {
        module_base = 0;
        if (!dll_name) {
            return status_invalid_parameter;
        }

        wchar_t full_path[260] = { 0 };
        const wchar_t* prefix = L"\\KnownDlls\\";
        size_t prefix_len = wcslen(prefix);
        size_t name_len = wcslen(dll_name);
        if ((prefix_len + name_len + 1) >= (sizeof(full_path) / sizeof(full_path[0]))) {
            return status_invalid_parameter;
        }

        for (size_t i = 0; i < prefix_len; ++i) {
            full_path[i] = prefix[i];
        }
        for (size_t i = 0; i < name_len; ++i) {
            full_path[prefix_len + i] = dll_name[i];
        }
        full_path[prefix_len + name_len] = L'\0';

        UNICODE_STRING name = { 0 };
        RtlInitUnicodeString(&name, full_path);

        OBJECT_ATTRIBUTES attr = { 0 };
        InitializeObjectAttributes(&attr, &name, OBJ_CASE_INSENSITIVE, 0, 0);

        HANDLE section = 0;
        NTSTATUS nt_status = ZwOpenSection(&section, SECTION_MAP_READ | SECTION_MAP_EXECUTE, &attr);
        if (!NT_SUCCESS(nt_status) || !section) {
            return status_failure;
        }

        SIZE_T view_size = 0;
        PVOID view_base = 0;
        nt_status = ZwMapViewOfSection(section, (HANDLE)-1, &view_base, 0, 0, 0, &view_size, ViewUnmap, 0, PAGE_READONLY);
        ZwClose(section);
        if (!NT_SUCCESS(nt_status) || !view_base) {
            return status_failure;
        }

        module_base = view_base;
        return status_success;
    }

    void unmap_module_view(void* module_base) {
        if (!module_base) {
            return;
        }

        ZwUnmapViewOfSection((HANDLE)-1, module_base);
    }

    void* get_export_address(void* module_base, const char* function_name) {
        if (!module_base || !function_name) {
            return 0;
        }

        IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)module_base;
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;
        }

        IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)((uintptr_t)module_base + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }

        IMAGE_DATA_DIRECTORY* export_dir_entry = &nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!export_dir_entry->VirtualAddress || !export_dir_entry->Size) {
            return 0;
        }

        IMAGE_EXPORT_DIRECTORY* export_dir = (IMAGE_EXPORT_DIRECTORY*)((uintptr_t)module_base + export_dir_entry->VirtualAddress);
        uint32_t* names = (uint32_t*)((uintptr_t)module_base + export_dir->AddressOfNames);
        uint16_t* ordinals = (uint16_t*)((uintptr_t)module_base + export_dir->AddressOfNameOrdinals);
        uint32_t* functions = (uint32_t*)((uintptr_t)module_base + export_dir->AddressOfFunctions);

        for (uint32_t i = 0; i < export_dir->NumberOfNames; ++i) {
            const char* curr_name = (const char*)((uintptr_t)module_base + names[i]);
            if (strcmp(curr_name, function_name) == 0) {
                uint16_t ord = ordinals[i];
                if (ord >= export_dir->NumberOfFunctions) {
                    return 0;
                }

                uintptr_t fn = (uintptr_t)module_base + functions[ord];
                return (void*)fn;
            }
        }

        return 0;
    }

    project_status get_win32k_service_table(void*& service_table) {
        service_table = 0;
        void* win32k_base = 0;
        project_status status = get_driver_module_base(L"win32k.sys", win32k_base);
        if (status != status_success) {
            return status;
        }

        service_table = get_export_address(win32k_base, "W32pServiceTable");
        return service_table ? status_success : status_failure;
    }

    project_status get_win32k_syscall_number(const char* function_name, uint32_t& syscall_number) {
        syscall_number = 0;
        if (!function_name || _strnicmp(function_name, "Nt", 2) != 0) {
            return status_invalid_parameter;
        }

        void* win32u_base = 0;
        project_status status = map_module_from_known_dll(L"win32u.dll", win32u_base);
        if (status != status_success || !win32u_base) {
            return status_failure;
        }

        void* export_address = get_export_address(win32u_base, function_name);
        if (!export_address) {
            unmap_module_view(win32u_base);
            return status_failure;
        }

        uint8_t* bytes = (uint8_t*)export_address;
        // win32u Nt* stubs contain: mov r10, rcx ; mov eax, imm32 ;
        if (bytes[3] != 0xB8) {
            unmap_module_view(win32u_base);
            return status_failure;
        }

        syscall_number = *(uint32_t*)(bytes + 4);
        unmap_module_view(win32u_base);
        return status_success;
    }

    project_status get_win32k_syscall_routine(void* win32k_sdt, const char* function_name, uint32_t syscall_number, void*& routine) {
        routine = 0;
        if (!win32k_sdt) {
            return status_invalid_parameter;
        }

        if (!syscall_number) {
            project_status status = get_win32k_syscall_number(function_name, syscall_number);
            if (status != status_success) {
                return status;
            }
        }

        int32_t routine_offset = *(int32_t*)((uintptr_t)win32k_sdt + ((syscall_number & 0xFFF) * sizeof(int32_t)));
        routine = (void*)((int64_t)win32k_sdt + (((int64_t)((uint32_t)routine_offset >> 4)) | 0xFFFFFFFFF0000000));
        return routine ? status_success : status_failure;
    }

};
