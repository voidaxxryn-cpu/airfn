#include "communication.hpp"

#include "../project_api.hpp"
#include "../project_utility.hpp"
#include "../offset_resolver.hpp"

extern "C" NTKERNELAPI ULONG PsGetProcessSessionId(_In_ PEPROCESS Process);

extern "C" info_page_t* g_info_page = 0;

namespace communication {
    /*
        Global variables
    */
    // Data pointer for communication with the driver
    void** g_data_ptr_address = 0;        ///< Pointer to the data address in memory
    void* g_orig_data_ptr_value = 0;      ///< Original data pointer value

    // Gadgets
    void* g_used_gadget = 0;              ///< The location where the data pointer will be pointed
    void* g_used_gadget_jump_destination = 0; ///< Destination for the jump in the gadget (mov rax, jmp rax)

    // Shellcodes
    void* enter_constructed_space_executed = 0; ///< Shellcode for entering constructed space (executed version)
    void* enter_constructed_space_shown = 0;    ///< Shellcode for entering constructed space (shown version)
    extern "C" void* exit_constructed_space = 0; ///< Shellcode for exiting constructed space
    extern "C" void* nmi_shellcode = 0;          ///< Non-maskable interrupt shellcode

    /*
        Utility functions
    */

    /**
     * @brief Logs information about the data pointer.
     *
     * This function logs the current state of the data pointer, including the
     * original value and the exchanged value, which can be useful for debugging
     * memory manipulation or communication processes.
     */
    void log_data_ptr_info(void) {
        project_log_info("Data ptr value stored at: %p", g_data_ptr_address);
        project_log_info("Orig data ptr value: %p", g_orig_data_ptr_value);
        project_log_info("Exchanged data ptr value: %p", asm_handler);
    }

    /*
        Initialization functions
    */
    namespace gadgets {
        /**
         * @brief Structure to hold gadget information.
         *
         * This structure is used to store information about a specific gadget,
         * including the gadget’s address and the jump destination for further execution.
         */
        struct gadget_info_t {
            void* gadget;             ///< Pointer to the gadget's code.
            void* jump_destination;   ///< Pointer to the destination where the gadget should jump.
        };

        /**
         * @brief Generates a simple pseudo-random number using a linear congruential generator.
         *
         * This function uses the Time Stamp Counter (TSC) value as a seed to initialize the random number generator,
         * and then applies a linear congruential generator (LCG) formula to produce a pseudo-random number.
         *
         * @return A pseudo-random 32-bit unsigned integer.
         */
        uint32_t simple_random() {
            uint32_t seed = 0;

            // If the seed is zero, initialize it using the TSC (Time Stamp Counter).
            if (!seed) {
                uint64_t tsc = __rdtsc();  // Get the current TSC value.
                seed = (uint32_t)(tsc ^ (tsc >> 32));  // XOR the TSC to generate a seed.
            }

            // Apply the Linear Congruential Generator (LCG) formula to generate a random number.
            seed = (1664525 * seed + 1013904223);  // LCG coefficients.
            return seed;
        }

        /**
         * @brief Finds possible gadget addresses within the win32kfull.sys module of the winlogon.exe process.
         *
         * This function searches for specific gadgets in the `win32kfull.sys` driver module, which is loaded
         * within the `winlogon.exe` process. It scans through the sections of the module to identify gadgets
         * using a pattern (`jmp near relative`). The function returns a list of gadget addresses and their
         * corresponding jump destinations. The search is done only within executable sections that are not discardable.
         *
         * @param gadget_count A reference to an integer that will hold the number of found gadgets.
         * @return A pointer to an array of `gadget_info_t` structures, each holding the address of a gadget and its
         *         corresponding jump destination. The memory for this array is allocated dynamically.
         */
        gadget_info_t* find_possible_gadgets(uint32_t& gadget_count) {
            PEPROCESS winlogon_eproc = 0;
            KAPC_STATE apc = { 0 };
            project_status status = status_success;
            void* win32k_base = 0;

            status = utility::get_eprocess_in_session("winlogon.exe", g_target_session_id, winlogon_eproc);
            if (status != status_success) {
                project_log_error("Failed to get winlogon.exe EPROCESS");
                return 0;
            }

            status = utility::get_driver_module_base(L"win32kfull.sys", win32k_base);
            if (status != status_success) {
                project_log_error("Failed to get win32kfull.sys base address");
                return 0;
            }


            KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);
            IMAGE_DOS_HEADER* dos_header = (IMAGE_DOS_HEADER*)win32k_base;
            if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
                KeUnstackDetachProcess(&apc);
                project_log_error("Invalid DOS headers");
                return 0;
            }

            IMAGE_NT_HEADERS64* nt_headers = (IMAGE_NT_HEADERS64*)((uintptr_t)win32k_base + dos_header->e_lfanew);
            if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
                KeUnstackDetachProcess(&apc);
                project_log_error("Invalid NT headers");
                return 0;
            }

			if (nt_headers->FileHeader.NumberOfSections == 0 || nt_headers->FileHeader.NumberOfSections > 100) {
				KeUnstackDetachProcess(&apc);
				project_log_error("Invalid section count: %d", nt_headers->FileHeader.NumberOfSections);
				return 0;
			}

            IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((uintptr_t)nt_headers + sizeof(IMAGE_NT_HEADERS64));
            gadget_info_t* gadget_addresses = (gadget_info_t*)ExAllocatePool(NonPagedPool, PAGE_SIZE);
            if (!gadget_addresses) {
                KeUnstackDetachProcess(&apc);
                project_log_error("Failed to alloc mem");
                return 0;
            }
            memset(gadget_addresses, 0, PAGE_SIZE);

            uint32_t found_gadgets = 0;
            const uint32_t MAX_GADGETS = (PAGE_SIZE / sizeof(gadget_info_t));

            for (uint32_t i = 0; i < nt_headers->FileHeader.NumberOfSections; i++) {
                if (!(sections[i].Characteristics & IMAGE_SCN_CNT_CODE) ||
                    !(sections[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) ||
                    (sections[i].Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
                    continue;

                uintptr_t section_start = (uintptr_t)win32k_base + sections[i].VirtualAddress;
                uint32_t section_size = sections[i].Misc.VirtualSize;

				if (!MmIsAddressValid((void*)section_start) || section_size == 0 || section_size > 50 * 1024 * 1024) {
					continue;
				}

                for (uint32_t curr_section_offset = 0; curr_section_offset + 6 < section_size; curr_section_offset++) {
                    if (found_gadgets >= MAX_GADGETS) {
                        goto cleanup;
                    }

                    uint8_t* curr = (uint8_t*)section_start + curr_section_offset;
                    uintptr_t result = 0;
                    uintptr_t next_instruction = 0;
                    uintptr_t jump_destination = 0;
                    bool found_candidate = false;

                    // Win10 common sequence: 90 E9 <rel32>
                    if (curr[0] == 0x90 && curr[1] == 0xE9 && (curr_section_offset + 6) < section_size) {
                        int32_t rel = *(int32_t*)(curr + 2);
                        result = (uintptr_t)curr;
                        next_instruction = result + 6;
                        jump_destination = next_instruction + rel;
                        found_candidate = true;
                    }
                    // Win11/newer builds often use plain E9 <rel32>
                    else if (curr[0] == 0xE9 && (curr_section_offset + 5) < section_size) {
                        int32_t rel = *(int32_t*)(curr + 1);
                        result = (uintptr_t)curr;
                        next_instruction = result + 5;
                        jump_destination = next_instruction + rel;
                        found_candidate = true;
                    }
                    // RIP-relative indirect jump: FF 25 <disp32>
                    else if (curr[0] == 0xFF && curr[1] == 0x25 && (curr_section_offset + 6) < section_size) {
                        int32_t disp = *(int32_t*)(curr + 2);
                        result = (uintptr_t)curr;
                        next_instruction = result + 6;
                        uintptr_t target_ptr_address = next_instruction + disp;
                        if (MmIsAddressValid((void*)target_ptr_address)) {
                            jump_destination = *(uintptr_t*)target_ptr_address;
                            found_candidate = (jump_destination != 0);
                        }
                    }

                    if (!found_candidate || !jump_destination) {
                        continue;
                    }

                    bool is_valid_va = MmIsAddressValid((void*)jump_destination) ? true : false;
                    project_status region_status = utility::is_data_ptr_in_valid_region((uint64_t)jump_destination);
                    bool looks_remappable_target = (!is_valid_va) || (region_status != status_success);

                    if (looks_remappable_target) {
                        gadget_addresses[found_gadgets].gadget = (void*)result;
                        gadget_addresses[found_gadgets].jump_destination = (void*)jump_destination;
                        found_gadgets++;
                    }
                }
            }

		cleanup:
            KeUnstackDetachProcess(&apc);
            gadget_count = found_gadgets;
            return gadget_addresses;
        }

        /**
         * @brief Maps a virtual memory page to a physical memory page by setting up page tables.
         *
         * This function checks if the necessary page tables exist for a given virtual address.
         * If they do not exist, it allocates memory for them, sets up the page table entries,
         * and maps the virtual memory address to a physical address.
         * It also invalidates the Translation Lookaside Buffer (TLB) to ensure the mapping is applied.
         *
         * @param memory The virtual memory address to be mapped.
         * @return project_status A status code indicating success or failure.
         */
        project_status win_map_memory_page(void* memory) {
            project_status status = status_success;
            PHYSICAL_ADDRESS max_addr = { 0 };
            max_addr.QuadPart = MAXULONG64;

            va_64_t mem_va;
            mem_va.flags = (uint64_t)memory;

            pml4e_64* pml4_table = 0;
            pdpte_64* pdpt_table = 0;
            pde_64* pde_table = 0;
            pte_64* pte_table = 0;

            uint64_t pml4_pa = __readcr3() & ~0xFFFULL;
            pml4_table = (pml4e_64*)win_get_virtual_address(pml4_pa);
            if (!pml4_table)
                return status_win_address_translation_failed;

            pdpt_table = (pdpte_64*)win_get_virtual_address(pml4_table[mem_va.pml4e_idx].page_frame_number << 12);
            if (!pdpt_table) {
                /*
                    Follow the principle of bottom to top (Pte->Pde->Pdpte->Pml4) when populating to avoid race conditions / logical errors
                */
                void* allocated_mem = MmAllocateContiguousMemory(0x1000, max_addr);
                if (!allocated_mem) {
                    return status_memory_allocation_failed;
                }

                memset(allocated_mem, 0, 0x1000);

                uint64_t mem_pfn = win_get_physical_address(allocated_mem) >> 12;
                if (!mem_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    return status_win_address_translation_failed;
                }

                pte_table = (pte_64*)MmAllocateContiguousMemory(0x1000, max_addr);
                if (!pte_table) {
                    MmFreeContiguousMemory(allocated_mem);
                    return status_memory_allocation_failed;
                }
                memset(pte_table, 0, 0x1000);

                uint64_t pte_pfn = win_get_physical_address(pte_table) >> 12;
                if (!pte_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    return status_win_address_translation_failed;
                }

                pde_table = (pde_64*)MmAllocateContiguousMemory(0x1000, max_addr);
                if (!pde_table) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    return status_memory_allocation_failed;
                }
                memset(pde_table, 0, 0x1000);

                uint64_t pde_pfn = win_get_physical_address(pde_table) >> 12;
                if (!pde_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    MmFreeContiguousMemory(pde_table);
                    return status_win_address_translation_failed;
                }

                pdpt_table = (pdpte_64*)MmAllocateContiguousMemory(0x1000, max_addr);
                if (!pdpt_table) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    MmFreeContiguousMemory(pde_table);
                    return status_memory_allocation_failed;
                }
                memset(pdpt_table, 0, 0x1000);

                uint64_t pdpte_pfn = win_get_physical_address(pdpt_table) >> 12;
                if (!pdpte_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    MmFreeContiguousMemory(pde_table);
                    MmFreeContiguousMemory(pdpt_table);
                    return status_win_address_translation_failed;
                }

                pte_table[mem_va.pte_idx].flags = 0;
                pte_table[mem_va.pte_idx].present = 1;
                pte_table[mem_va.pte_idx].write = 1;
                pte_table[mem_va.pte_idx].global = 1;
                pte_table[mem_va.pte_idx].execute_disable = 0;
                pte_table[mem_va.pte_idx].page_frame_number = mem_pfn;

                pde_table[mem_va.pde_idx].flags = 0;
                pde_table[mem_va.pde_idx].present = 1;
                pde_table[mem_va.pde_idx].write = 1;
                pde_table[mem_va.pde_idx].execute_disable = 0;
                pde_table[mem_va.pde_idx].page_frame_number = pte_pfn;

                pdpt_table[mem_va.pdpte_idx].flags = 0;
                pdpt_table[mem_va.pdpte_idx].present = 1;
                pdpt_table[mem_va.pdpte_idx].write = 1;
                pdpt_table[mem_va.pdpte_idx].execute_disable = 0;
                pdpt_table[mem_va.pdpte_idx].page_frame_number = pde_pfn;

                pml4_table[mem_va.pml4e_idx].flags = 0;
                pml4_table[mem_va.pml4e_idx].present = 1;
                pml4_table[mem_va.pml4e_idx].write = 1;
                pml4_table[mem_va.pml4e_idx].execute_disable = 0;
                pml4_table[mem_va.pml4e_idx].page_frame_number = pdpte_pfn;

                __invlpg(memory);

                return status;
            }

            pde_table = (pde_64*)win_get_virtual_address(pdpt_table[mem_va.pdpte_idx].page_frame_number << 12);
            if (!pde_table) {
                /*
                    Follow the principle of bottom to top (Pte->Pde->Pdpte->Pml4) when populating to avoid race conditions / logical errors
                */
                void* allocated_mem = MmAllocateContiguousMemory(0x1000, max_addr);
                if (!allocated_mem) {
                    return status_memory_allocation_failed;
                }


                memset(allocated_mem, 0, 0x1000);

                uint64_t mem_pfn = win_get_physical_address(allocated_mem) >> 12;
                if (!mem_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    return status_win_address_translation_failed;
                }

                pte_table = (pte_64*)MmAllocateContiguousMemory(0x1000, max_addr);
                if (!pte_table) {
                    MmFreeContiguousMemory(allocated_mem);
                    return status_memory_allocation_failed;
                }
                memset(pte_table, 0, 0x1000);

                uint64_t pte_pfn = win_get_physical_address(pte_table) >> 12;
                if (!pte_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    return status_win_address_translation_failed;
                }

                pde_table = (pde_64*)MmAllocateContiguousMemory(0x1000, max_addr);
                if (!pde_table) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    return status_memory_allocation_failed;
                }
                memset(pde_table, 0, 0x1000);

                uint64_t pde_pfn = win_get_physical_address(pde_table) >> 12;
                if (!pde_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    MmFreeContiguousMemory(pde_table);
                    return status_win_address_translation_failed;
                }

                pte_table[mem_va.pte_idx].flags = 0;
                pte_table[mem_va.pte_idx].present = 1;
                pte_table[mem_va.pte_idx].write = 1;
                pte_table[mem_va.pte_idx].global = 1;
                pte_table[mem_va.pte_idx].execute_disable = 0;
                pte_table[mem_va.pte_idx].page_frame_number = mem_pfn;

                pde_table[mem_va.pde_idx].flags = 0;
                pde_table[mem_va.pde_idx].present = 1;
                pde_table[mem_va.pde_idx].write = 1;
                pde_table[mem_va.pde_idx].execute_disable = 0;
                pde_table[mem_va.pde_idx].page_frame_number = pte_pfn;

                pdpt_table[mem_va.pdpte_idx].flags = 0;
                pdpt_table[mem_va.pdpte_idx].present = 1;
                pdpt_table[mem_va.pdpte_idx].write = 1;
                pdpt_table[mem_va.pdpte_idx].execute_disable = 0;
                pdpt_table[mem_va.pdpte_idx].page_frame_number = pde_pfn;

                __invlpg(memory);

                return status;
            }

            pte_table = (pte_64*)win_get_virtual_address(pde_table[mem_va.pde_idx].page_frame_number << 12);
            if (!pte_table) {
                /*
                    Follow the principle of bottom to top (Pte->Pde->Pdpte->Pml4) when populating to avoid race conditions / logical errors
                */
                void* allocated_mem = MmAllocateContiguousMemory(0x1000, max_addr);
                if (!allocated_mem) {
                    return status_memory_allocation_failed;
                }


                memset(allocated_mem, 0, 0x1000);

                uint64_t mem_pfn = win_get_physical_address(allocated_mem) >> 12;
                if (!mem_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    return status_win_address_translation_failed;
                }

                pte_table = (pte_64*)MmAllocateContiguousMemory(0x1000, max_addr);
                if (!pte_table) {
                    MmFreeContiguousMemory(allocated_mem);
                    return status_memory_allocation_failed;
                }
                memset(pte_table, 0, 0x1000);

                uint64_t pte_pfn = win_get_physical_address(pte_table) >> 12;
                if (!pte_pfn) {
                    MmFreeContiguousMemory(allocated_mem);
                    MmFreeContiguousMemory(pte_table);
                    return status_win_address_translation_failed;
                }

                pte_table[mem_va.pte_idx].flags = 0;
                pte_table[mem_va.pte_idx].present = 1;
                pte_table[mem_va.pte_idx].write = 1;
                pte_table[mem_va.pte_idx].global = 1;
                pte_table[mem_va.pte_idx].execute_disable = 0;
                pte_table[mem_va.pte_idx].page_frame_number = mem_pfn;

                pde_table[mem_va.pde_idx].flags = 0;
                pde_table[mem_va.pde_idx].present = 1;
                pde_table[mem_va.pde_idx].write = 1;
                pde_table[mem_va.pde_idx].execute_disable = 0;
                pde_table[mem_va.pde_idx].page_frame_number = pte_pfn;

                __invlpg(memory);

                return status;
            }

            void* allocated_mem = MmAllocateContiguousMemory(0x1000, max_addr);
            if (!allocated_mem) {
                return status_memory_allocation_failed;
            }

            memset(allocated_mem, 0, 0x1000);

            uint64_t mem_pfn = win_get_physical_address(allocated_mem) >> 12;
            if (!mem_pfn) {
                MmFreeContiguousMemory(allocated_mem);
                return status_win_address_translation_failed;
            }

            pte_table[mem_va.pte_idx].flags = 0;
            pte_table[mem_va.pte_idx].present = 1;
            pte_table[mem_va.pte_idx].write = 1;
            pte_table[mem_va.pte_idx].global = 1;
            pte_table[mem_va.pte_idx].execute_disable = 0;
            pte_table[mem_va.pte_idx].page_frame_number = mem_pfn;

            __invlpg(memory);

            return status;
        }

        /**
         * @brief Generates a jump shellcode that transfers control to the specified shown shellcode.
         *
         * This function constructs a jump shellcode that moves the address of the target shellcode
         * into the `rax` register and then performs a `jmp rax` to transfer control to that address.
         * The generated shellcode is copied into the memory location provided by `validated_jump_destination`.
         *
         * @param validated_jump_destination A pointer to the memory location where the jump shellcode will be written.
         * @param shown_shellcode A pointer to the target shellcode address to which the jump will be made.
         *
         * @note Both `validated_jump_destination` and `shown_shellcode` should be valid, mapped memory addresses.
         */
        void generate_jmp_shellcode(void* validated_jump_destination, void* shown_shellcode) {
            if (!validated_jump_destination || !shown_shellcode)  ///< Check if the parameters are valid
                return;

            static const uint8_t jump_shown_shellcode[] = {
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, ///< mov rax, imm64 (address of handler_address)
                0xFF, 0xE0,                                                 ///< jmp rax
            };

            *(void**)((uint8_t*)jump_shown_shellcode + 2) = shown_shellcode; ///< Inject the target shellcode address

            memcpy(validated_jump_destination, jump_shown_shellcode, sizeof(jump_shown_shellcode)); ///< Copy the shellcode to the destination
        }

        /**
         * @brief Logs information about a selected gadget.
         *
         * This function logs the count of found gadgets and details about the selected gadget,
         * including its address and the destination it points to.
         *
         * @param gadget_count The total number of gadgets found.
         * @param random_index The index of the selected gadget.
         * @param selected_gadget The selected gadget's details, including its address and jump destination.
         */
        void log_gadget_info(uint32_t gadget_count, uint32_t random_index, gadget_info_t& selected_gadget) {
            project_log_info("Found %d gadgets", gadget_count);
            project_log_info("[%d] Selected gadget at %p points to %p", random_index, selected_gadget.gadget, selected_gadget.jump_destination);
        }
        /**
         * @brief Initializes gadgets by finding available gadgets and mapping memory for the jump destination.
         *
         * This function finds the available gadgets within `win32kfull.sys`, selects a random gadget,
         * and then maps the memory of the jump destination for that gadget. Once mapped, it generates
         * the shellcode to jump to the selected gadget's destination. The shellcode is then used to
         * modify control flow.
         *
         * @param shown_shellcode A pointer to the shellcode to be executed once the jump occurs.
         *
         * @return project_status Returns `status_success` if gadgets are successfully initialized,
         *         or an error status if initialization fails.
         */
        project_status init_gadgets(void* shown_shellcode) {
            uint32_t gadget_count = 0;
            gadget_info_t* gadgets = find_possible_gadgets(gadget_count);
            if (!gadgets || !gadget_count) {
                project_log_error("Failed to find gadgets in win32kfull.sys %p %d", gadgets, gadget_count);
                return status_no_gadget_found;
            }

            uint32_t random_index = simple_random() % gadget_count;
            gadget_info_t& selected_gadget = gadgets[random_index];

            project_log_info("Gadget pool: %u | selected idx %u | gadget %p -> jump_dest %p",
                gadget_count, random_index, selected_gadget.gadget, selected_gadget.jump_destination);

            // Now we have to map the memory this points to in windows' cr3
            project_status status = win_map_memory_page(selected_gadget.jump_destination);
            if (status != status_success) {
                project_log_error("Failed to map the gadget jump destination");
                ExFreePool(gadgets);
                return status;
            }

                generate_jmp_shellcode(selected_gadget.jump_destination, shown_shellcode);

            g_used_gadget = selected_gadget.gadget;
            g_used_gadget_jump_destination = selected_gadget.jump_destination;

            ExFreePool(gadgets);
            return status_success;
        }
    };

    /**
     * @brief Checks if the data pointer has already been hooked.
     *
     * This function checks whether the data pointer points to a valid region and if it matches
     * a known pattern indicating that it has already been hooked. The function attaches to the
     * `winlogon.exe` process, verifies the data pointer, and inspects the pattern to determine
     * if it has been modified (i.e., hooked).
     *
     * @param data_ptr_address The address of the data pointer to be checked.
     * @param winlogon_eproc The `EPROCESS` of the `winlogon.exe` process to which we attach.
     *
     * @return project_status Returns `status_success` if the data pointer is valid and not hooked,
     *         or an error status if the pointer is invalid or already hooked.
     */
    project_status is_already_hooked(void** data_ptr_address, PEPROCESS winlogon_eproc) {
        KAPC_STATE apc = { 0 };
        project_status status;

        KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);
        // First check if it points to a valid region
        status = utility::is_data_ptr_in_valid_region((uint64_t)*data_ptr_address);
        if (status != status_success) {
            KeUnstackDetachProcess(&apc);
            project_log_error("[INVALID MODULE] Data ptr at: %p already hooked", data_ptr_address);
            return status;
        }

        // Then check whether the pattern it points to matches our pattern (indicating it already being hooked)
        uint8_t* target_bytes = (uint8_t*)*data_ptr_address;
        if (target_bytes[0] == 0x90 &&
            target_bytes[1] == 0xE9) {
            KeUnstackDetachProcess(&apc);
            project_log_warning("[VALID MODULE] Data ptr at: %p already hooked - Chaining hooks...", data_ptr_address);
            return status_success;
        }

        KeUnstackDetachProcess(&apc);

        return status_success;
    }

    static ULONG get_windows_build_number(void) {
        RTL_OSVERSIONINFOW version_info = { 0 };
        version_info.dwOSVersionInfoSize = sizeof(version_info);
        if (NT_SUCCESS(RtlGetVersion(&version_info))) {
            return version_info.dwBuildNumber;
        }

        return 0;
    }

    static project_status resolve_data_ptr_legacy_patterns(void** data_ptr_address, void** orig_data_ptr_value) {
        if (!data_ptr_address || !orig_data_ptr_value) {
            return status_invalid_parameter;
        }

        project_status status = status_success;
        void* win32k_base = 0;
        PEPROCESS winlogon_eproc = 0;
        KAPC_STATE apc = { 0 };
        bool attached = false;

        const char* patterns[8] = { "\x48\x83\xEC\x28\x48\x8B\x05\x99\x02", "\x48\x83\xEC\x28\x48\x8B\x05\x59\x02", "\x48\x83\xEC\x28\x48\x8B\x05\xF5\x9C", "\x48\x83\xEC\x28\x48\x8B\x05\x75\x94", "\x48\x83\xEC\x28\x48\x8B\x05\x05\x9D", "\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\x44\x8B\x54\x24\x00\x44\x89\x54\x24\x00\x4C\x8B\x54\x24" , "\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x33\xC9", "\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x00\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x48\x83\xEC\x00\x48\x8B\x05\x00\x00\x00\x00\x48\x85\xC0\x74\x00\x44\x8B\x54\x24\x00\x44\x89\x54\x24\x00\x4C\x8B\x54\x24" };

        uint64_t function = 0;

        int* displacement_ptr = 0;
        uint64_t target_address = 0;
        uint64_t orig_data_ptr = 0;

        status = utility::get_driver_module_base(L"win32k.sys", win32k_base);
        if (status != status_success) {
            project_log_error("Failed to get win32k.sys base address");
            goto cleanup;
        }

        // Validate win32k_base
        if (!MmIsAddressValid(win32k_base)) {
            project_log_error("Invalid win32k.sys base address");
            status = status_failure;
            goto cleanup;
        }

        status = utility::get_eprocess_in_session("winlogon.exe", g_target_session_id, winlogon_eproc);
        if (status != status_success) {
            project_log_error("Failed to get winlogon.exe eproc");
            goto cleanup;
        }

        KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);
        attached = true;

        // NtUserGetCPD
        for (const auto& pattern : patterns) {
            function = utility::search_pattern_in_section(win32k_base, ".text", pattern, 9, 0x0);
            if (function)
                break;
        }

        if (!function) {
            status = status_failure;
            if (attached) {
                KeUnstackDetachProcess(&apc);
                attached = false;
            }
            project_log_error("Failed to find NtUserGetCPD; You are maybe running the wrong winver");
            goto cleanup;
        }

        // Validate function address
        if (!MmIsAddressValid((void*)function)) {
            if (attached) {
                KeUnstackDetachProcess(&apc);
                attached = false;
            }
            project_log_error("Invalid function address");
            status = status_failure;
            goto cleanup;
        }

        displacement_ptr = (int*)(function + 7);
        target_address = function + 7 + 4 + *displacement_ptr;
        if (!target_address || !MmIsAddressValid((void*)target_address)) {
            if (attached) {
                KeUnstackDetachProcess(&apc);
                attached = false;
            }
            project_log_error("Failed to find data ptr address or invalid address");
            status = status_failure;
            goto cleanup;
        }

        orig_data_ptr = *(uint64_t*)target_address;
        KeUnstackDetachProcess(&apc);
        attached = false;

        status = is_already_hooked((void**)target_address, winlogon_eproc);
        if (status != status_success)
            return status;

        *data_ptr_address = (void*)target_address;
        *orig_data_ptr_value = (void*)orig_data_ptr;

    cleanup:
        if (attached) {
            KeUnstackDetachProcess(&apc);
        }
        return status;
    }

    static bool decode_mov_mem_disp(const uint8_t* instruction, uint32_t remaining, uint32_t& length, int32_t& displacement) {
        length = 0;
        displacement = 0;
        if (!instruction || remaining < 2) {
            return false;
        }

        uint32_t idx = 0;
        if ((instruction[idx] & 0xF0) == 0x40) { // optional REX prefix
            idx++;
            if (remaining <= idx + 1) {
                return false;
            }
        }

        if (instruction[idx] != 0x8B) { // mov r64, r/m64
            return false;
        }
        idx++;

        uint8_t modrm = instruction[idx++];
        uint8_t mod = (modrm >> 6) & 0x3;
        uint8_t rm = modrm & 0x7;

        if (mod == 3) {
            return false; // register operand, not memory dereference
        }

        if (rm == 4) { // SIB byte present
            if (remaining <= idx) {
                return false;
            }
            idx++;
        }

        if (mod == 0) {
            if (rm == 5) { // disp32 only
                if (remaining < idx + 4) {
                    return false;
                }
                displacement = *(int32_t*)(instruction + idx);
                idx += 4;
            }
            else {
                return false; // no displacement => not useful for our offset extraction
            }
        }
        else if (mod == 1) { // disp8
            if (remaining < idx + 1) {
                return false;
            }
            displacement = (int32_t)(int8_t)instruction[idx];
            idx += 1;
        }
        else if (mod == 2) { // disp32
            if (remaining < idx + 4) {
                return false;
            }
            displacement = *(int32_t*)(instruction + idx);
            idx += 4;
        }

        length = idx;
        return true;
    }

    static bool extract_dynamic_session_offsets(uint8_t* routine, int32_t& session_offset_0, int32_t& session_offset_1, int32_t& session_offset_2) {
        if (!routine) {
            return false;
        }

        for (uint32_t i = 0; i < 0x50; ++i) {
            if (routine[i] != 0xE8) { // call rel32
                continue;
            }

            uint32_t cursor = i + 5;
            int32_t found_offsets[3] = { 0 };
            uint32_t found_count = 0;

            const uint32_t max_probe_size = 0x120;
            while (cursor < (i + 0x50) && found_count < 3) {
                uint32_t ins_len = 0;
                int32_t disp = 0;
                uint32_t remaining = (cursor < max_probe_size) ? (max_probe_size - cursor) : 0;
                if (remaining && decode_mov_mem_disp(routine + cursor, remaining, ins_len, disp)) {
                    found_offsets[found_count++] = disp;
                    cursor += ins_len;
                }
                else {
                    cursor++;
                }
            }

            if (found_count == 3) {
                session_offset_0 = found_offsets[0];
                session_offset_1 = found_offsets[1];
                session_offset_2 = found_offsets[2];
                return true;
            }
        }

        return false;
    }

    static project_status resolve_data_ptr_dynamic_session(void** data_ptr_address, void** orig_data_ptr_value) {
        if (!data_ptr_address || !orig_data_ptr_value) {
            return status_invalid_parameter;
        }

        project_status status = status_success;
        PEPROCESS winlogon_eproc = 0;
        KAPC_STATE apc = { 0 };
        bool attached = false;
        void* win32k_base = 0;
        void* session_state = 0;
        void* win32k_sdt = 0;
        void* routine = 0;
        void* w32_get_session_state = 0;
        int32_t session_offset_0 = 0;
        int32_t session_offset_1 = 0;
        int32_t session_offset_2 = 0;
        uint64_t layer0_ptr = 0;
        uint64_t layer1_ptr = 0;
        uint64_t target_address = 0;
        uint64_t orig_data_ptr = 0;

        status = utility::get_eprocess_in_session("winlogon.exe", g_target_session_id, winlogon_eproc);
        if (status != status_success) {
            project_log_error("Dynamic resolver failed getting winlogon EPROCESS");
            return status;
        }

        status = utility::get_driver_module_base(L"win32k.sys", win32k_base);
        if (status != status_success || !win32k_base) {
            project_log_error("Dynamic resolver failed getting win32k.sys");
            return status_failure;
        }

        w32_get_session_state = utility::get_export_address(win32k_base, "W32GetSessionState");
        if (!w32_get_session_state) {
            project_log_error("Dynamic resolver missing W32GetSessionState export");
            return status_failure;
        }

        status = utility::get_win32k_service_table(win32k_sdt);
        if (status != status_success || !win32k_sdt) {
            project_log_error("Dynamic resolver missing W32pServiceTable");
            return status_failure;
        }

        const char* resolver_routines[] = {
            "NtUserGetCPD",
            "NtGdiBitBlt"
        };
        const char* selected_resolver_routine = 0;
        for (uint32_t i = 0; i < (sizeof(resolver_routines) / sizeof(resolver_routines[0])); ++i) {
            routine = 0;
            status = utility::get_win32k_syscall_routine(win32k_sdt, resolver_routines[i], 0, routine);
            if (status == status_success && routine && MmIsAddressValid(routine)) {
                selected_resolver_routine = resolver_routines[i];
                break;
            }
        }
        if (!selected_resolver_routine) {
            project_log_error("Dynamic resolver failed getting win32k syscall routine");
            return status_failure;
        }

        KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);
        attached = true;
        session_state = ((void*(*)())w32_get_session_state)();
        if (!session_state || !MmIsAddressValid(session_state)) {
            status = status_failure;
            project_log_error("Dynamic resolver failed getting session state");
            goto cleanup;
        }

        if (!extract_dynamic_session_offsets((uint8_t*)routine, session_offset_0, session_offset_1, session_offset_2)) {
            status = status_failure;
            project_log_error("Dynamic resolver failed extracting session offsets");
            goto cleanup;
        }

        layer0_ptr = *(uint64_t*)((uint8_t*)session_state + session_offset_0);
        if (!layer0_ptr || !MmIsAddressValid((void*)layer0_ptr)) {
            status = status_failure;
            project_log_error("Dynamic resolver invalid layer0 pointer");
            goto cleanup;
        }

        layer1_ptr = *(uint64_t*)((uint8_t*)layer0_ptr + session_offset_1);
        if (!layer1_ptr || !MmIsAddressValid((void*)layer1_ptr)) {
            status = status_failure;
            project_log_error("Dynamic resolver invalid layer1 pointer");
            goto cleanup;
        }

        target_address = layer1_ptr + session_offset_2;
        if (!target_address || !MmIsAddressValid((void*)target_address)) {
            status = status_failure;
            project_log_error("Dynamic resolver invalid target address");
            goto cleanup;
        }

        orig_data_ptr = *(uint64_t*)target_address;
        if (!orig_data_ptr || !MmIsAddressValid((void*)orig_data_ptr)) {
            status = status_failure;
            project_log_error("Dynamic resolver invalid original pointer value");
            goto cleanup;
        }

        KeUnstackDetachProcess(&apc);
        attached = false;

        status = is_already_hooked((void**)target_address, winlogon_eproc);
        if (status != status_success) {
            return status;
        }

        *data_ptr_address = (void*)target_address;
        *orig_data_ptr_value = (void*)orig_data_ptr;
        project_log_info("Dynamic resolver routine: %s", selected_resolver_routine);
        return status_success;

    cleanup:
        if (attached) {
            KeUnstackDetachProcess(&apc);
        }
        return status;
    }

    /**
     * @brief Initializes the data pointer by finding and validating the target address.
     *
     * This function uses both a legacy pattern-based resolver and a dynamic session-based
     * resolver. Resolver priority is selected by OS build and each path can fallback to the other.
     *
     * @return project_status Returns `status_success` if initialization was successful, or an error status
     *         if the process fails at any stage.
     */
    project_status init_data_ptr_data(void) {
        project_status status = status_failure;
        void* data_ptr_address = 0;
        void* orig_data_ptr = 0;
        ULONG build_number = get_windows_build_number();

        bool prefer_dynamic = (build_number >= 22000);
        if (prefer_dynamic) {
            status = resolve_data_ptr_dynamic_session(&data_ptr_address, &orig_data_ptr);
            if (status == status_success) {
                project_log_info("Data ptr resolved via dynamic session resolver (build %lu)", build_number);
            }
            else {
                project_log_warning("Dynamic session resolver failed, falling back to legacy pattern resolver");
                status = resolve_data_ptr_legacy_patterns(&data_ptr_address, &orig_data_ptr);
            }
        }
        else {
            status = resolve_data_ptr_legacy_patterns(&data_ptr_address, &orig_data_ptr);
            if (status == status_success) {
                project_log_info("Data ptr resolved via legacy pattern resolver (build %lu)", build_number);
            }
            else {
                project_log_warning("Legacy pattern resolver failed, falling back to dynamic session resolver");
                status = resolve_data_ptr_dynamic_session(&data_ptr_address, &orig_data_ptr);
            }
        }

        if (status != status_success || !data_ptr_address || !orig_data_ptr) {
            project_log_error("Failed resolving data ptr via both resolvers");
            return status_failure;
        }

        g_data_ptr_address = (void**)data_ptr_address;
        g_orig_data_ptr_value = orig_data_ptr;
        return status_success;
    }

    /**
     * @brief Initializes the CR3 mappings to ensure the driver is mapped even after removal from system page tables.
     *
     * This function ensures that the memory range of the driver is mapped in the current CR3, so that it remains accessible.
     * It also partially hides the shellcode by overwriting the virtual address mappings.
     *
     * @param driver_base Base address of the driver.
     * @param driver_size Size of the driver.
     *
     * @return project_status Returns `status_success` if successful, or an error status if the process fails.
     */
    project_status init_cr3_mappings(void* driver_base, uint64_t driver_size) {

        // Ensure the driver is mapped in our cr3 even after removed from system page tables
        project_status status = physmem::remapping::ensure_memory_mapping_for_range(driver_base, driver_size, utility::get_cr3(4));
        if (status != status_success)
            return status;

        // Partially hide the shellcode
        status = physmem::remapping::overwrite_virtual_address_mapping(enter_constructed_space_shown, enter_constructed_space_executed,
            physmem::util::get_system_cr3().flags, physmem::util::get_system_cr3().flags);
        if (status != status_success)
            return status;

        return status;
    }
    /**
     * @brief Initializes the data pointer hook by swapping the data pointer value with the new one.
     *
     * This function attaches to the `winlogon.exe` process, and then swaps the value at the given `data_ptr_address`
     * with the new `new_data_ptr_value` using `InterlockedExchangePointer`.
     *
     * @param data_ptr_address Pointer to the data pointer to be swapped.
     * @param new_data_ptr_value The new value to set at the data pointer address.
     *
     * @return project_status Returns `status_success` if successful, or an error status if the process fails.
     */
    project_status init_data_ptr_hook(void** data_ptr_address, void* new_data_ptr_value) {
        if (!data_ptr_address || !new_data_ptr_value)
            return status_invalid_parameter;

        project_status status = status_success;
        PEPROCESS winlogon_eproc = 0;
        KAPC_STATE apc = { 0 };

        status = utility::get_eprocess_in_session("winlogon.exe", g_target_session_id, winlogon_eproc);
        if (status != status_success) {
            project_log_error("Failed to get winlogon.exe EPROCESS");
            return status;
        }

        ULONG winlogon_session = PsGetProcessSessionId(winlogon_eproc);

        KeStackAttachProcess((PRKPROCESS)winlogon_eproc, &apc);

        void* old_value = InterlockedExchangePointer((void**)data_ptr_address, (void*)new_data_ptr_value);
        project_log_info("Data ptr hook: addr=%p old=%p new=%p winlogon_session=%lu",
            data_ptr_address, old_value, new_data_ptr_value, winlogon_session);

        KeUnstackDetachProcess(&apc);
        return status;
    }
    /**
     * @brief Logs the shellcode pointers used in the system.
     *
     * This function logs the addresses of different shellcode segments, such as the entering shellcode, exiting shellcode,
     * and the NMI (Non-Maskable Interrupt) shellcode.
     */
    void log_shellcode_ptrs(void) {
        project_log_info("Shown entering shellcode at %p", enter_constructed_space_shown);
        project_log_info("Executed entering shellcode at %p", enter_constructed_space_executed);
        project_log_info("Exiting shellcode at %p", exit_constructed_space);
        project_log_info("Nmi shellcode at %p", nmi_shellcode);
    }
    /**
     * @brief Initializes the communication setup by performing several initialization steps.
     *
     * This function calls a series of initialization functions to set up the data pointer, shellcodes, CR3 mappings, gadgets,
     * and hooks for communication. It ensures all necessary components are set up before the system is ready for use.
     *
     * @param driver_base Base address of the driver.
     * @param driver_size Size of the driver.
     *
     * @return project_status Returns `status_success` if successful, or an error status if the process fails.
     */
    project_status init_communication(void* driver_base, uint64_t driver_size) {
        project_status status = status_success;

        status = init_data_ptr_data();
        if (status != status_success)
            return status;

        status = shellcode::construct_shellcodes(enter_constructed_space_executed, enter_constructed_space_shown,
            exit_constructed_space, nmi_shellcode,
            interrupts::get_constructed_idt_ptr(), g_orig_data_ptr_value,
            asm_handler, physmem::util::get_constructed_cr3().flags);
        if (status != status_success)
            return status;

        status = init_cr3_mappings(driver_base, driver_size);
        if (status != status_success)
            return status;

        status = gadgets::init_gadgets(enter_constructed_space_shown);
        if (status != status_success)
            return status;

        status = init_data_ptr_hook(g_data_ptr_address, g_used_gadget);
        if (status != status_success)
            return status;

        return status;
    }
    /**
     * @brief Unhooks the data pointer and restores its original value.
     *
     * This function restores the original value of the data pointer by copying the original value back and unmapping
     * the memory used for gadgets to ensure no memory leaks or remaining mappings. It ensures that the system is
     * returned to its pre-hooked state.
     *
     * @return project_status Returns `status_success` if successful, or an error status if the process fails.
     */
    project_status unhook_data_ptr(void) {
        if (!g_data_ptr_address || !g_orig_data_ptr_value) {
            logging::root_printf("Invalid unhook data");
            return status_failure;
        }

        // Basically revert the data ptr swap
        project_status status = physmem::runtime::copy_memory_from_constructed_cr3(g_data_ptr_address, &g_orig_data_ptr_value,
            sizeof(void*), shellcode::get_current_user_cr3());
        if (status != status_success) {
            logging::root_printf("Failed restoring data ptr swap");
            return status;
        }

        // Unmap our gadget in order to not run out of gadgets to use when reloading the driver
        status = physmem::paging_manipulation::win_unmap_memory_range(g_used_gadget_jump_destination, shellcode::get_current_user_cr3(), 0x1000);
        if (status != status_success) {
            logging::root_printf("Failed unmapping win gadgets memory range");
            return status;
        }

        return status;
    }
};
