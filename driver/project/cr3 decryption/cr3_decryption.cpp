#include "cr3_decryption.hpp"
#include "../offset_resolver.hpp"

namespace cr3_decryption {
	/**
	 * @brief Global variables used for CR3 decryption.
	 *
	 * These global variables store the base addresses of page tables and related data structures.
	 * They are initialized during the execution of `init_eac_cr3_decryption`.
	 */
	bool initialized = false; /**< Indicates whether CR3 decryption has been initialized */
	uint64_t pte_base = 0; /**< Base address for the Page Table Entry (PTE) */
	uint64_t pde_base = 0; /**< Base address for the Page Directory Entry (PDE) */
	uint64_t pdpte_base = 0; /**< Base address for the Page Directory Pointer Table Entry (PDPTE) */
	uint64_t pml4e_base = 0; /**< Base address for the PML4 entry */

	/**
	 * @brief The PTE base used for CR3 decryption.
	 *
	 * This variable holds the calculated base address of the PTE to be used in the CR3 decryption process.
	 */
	uint64_t cr3_ptebase = 0;

	/**
	 * @brief Global pointer to the physical memory ranges.
	 *
	 * This pointer holds the physical memory ranges, which are fetched during initialization.
	 */
	PPHYSICAL_MEMORY_RANGE memory_ranges = 0;

	/**
	 * @brief Pointer to the MmPfn database.
	 *
	 * This pointer will point to the resolved base address of the MmPfnDataBase, which is necessary
	 * for the page frame information during CR3 decryption.
	 */
	_MMPFN* mm_pfn_database = 0;

	/**
	 * @brief Initializes the EAC CR3 decryption process.
	 *
	 * This function sets up the required structures and initializes memory-related pointers used
	 * for CR3 decryption. It also finds key memory structures such as the MmPfnDataBase and page tables.
	 *
	 * @return A `project_status` code indicating success or failure of the initialization.
	 */
	project_status init_eac_cr3_decryption(void) {
		if (!physmem::is_initialized()) {
			project_log_info("Physmem was not initialized!");
			return status_failure;
		}

		// Get kernel base and PDB-resolved offsets from mapper
		uint64_t kernel_base;
		project_status status = utility::get_driver_module_base(L"ntoskrnl.exe", (void*&)kernel_base);
		if (status != status_success || !kernel_base) {
			project_log_info("Failed to get kernel base");
			return status_failure;
		}

		// Use PDB-resolved MmPfnDatabase RVA from mapper
		uint64_t mm_pfn_database_rva = offset_resolver::get_mm_pfn_database_rva();
		if (!mm_pfn_database_rva) {
			project_log_error("Failed to get MmPfnDatabase RVA from mapper");
			return status_failure;
		}

		uint64_t mm_pfn_database_address = kernel_base + mm_pfn_database_rva;
		mm_pfn_database = *(_MMPFN**)mm_pfn_database_address;
		project_log_info("Resolved MmPfnDatabase at 0x%llX (RVA: 0x%llX)", mm_pfn_database_address, mm_pfn_database_rva);

		// Use PDB-resolved MiGetPageTablePfnBuddyRaw RVA from mapper
		uint64_t mi_buddy_rva = offset_resolver::get_mi_get_page_table_pfn_buddy_rva();
		if (mi_buddy_rva) {
			uint64_t mi_buddy_address = kernel_base + mi_buddy_rva;
			g_MiGetPageTablePfnBuddyRaw = reinterpret_cast<uint64_t(__fastcall*)(const _MMPFN&)>(mi_buddy_address);
			project_log_info("Resolved MiGetPageTablePfnBuddyRaw at 0x%llX (RVA: 0x%llX)", mi_buddy_address, mi_buddy_rva);
		}
		else {
			project_log_warning("MiGetPageTablePfnBuddyRaw RVA not available from mapper; fallback will be used");
		}


		cr3 sys_cr3;
		sys_cr3.flags = __readcr3(); // We do not want to use the kernel cr3, but rather the one that our mapper had or any non kernel one ig
		uint64_t phys_system_directory = sys_cr3.address_of_page_directory << 12;
		pml4e_64* system_directory = (pml4e_64*)win_get_virtual_address(phys_system_directory);
		if (!system_directory)
			return status_win_address_translation_failed;

		// Find the self ref entry
		for (uint64_t i = 0; i < 512; i++) {
			if (system_directory[i].page_frame_number != sys_cr3.address_of_page_directory)
				continue;

			pml4e_base = (i + 0x1FFFE00ui64) << 39ui64;
			pdpte_base = (i << 30ui64) + pml4e_base;
			pde_base = (i << 30ui64) + pml4e_base + (i << 21ui64);
			pte_base = (i << 12ui64) + pde_base;

			cr3_ptebase = i * 8 + pte_base;

			break;
		}

		memory_ranges = MmGetPhysicalMemoryRanges();
		if (!memory_ranges) {
			project_log_info("Failed to get physical memory ranges");
			return status_failure;
		}

		initialized = true;

		return status_success;
	}

	/*
		Runtime
	*/
	namespace eproc {
		/**
		 * @brief Retrieves the CR3 (Page Directory Base Address) for a given process ID (PID).
		 *
		 * This function scans through the system's physical memory ranges and attempts to locate
		 * the CR3 address corresponding to the specified target process. It uses information about
		 * page frames and process structures to locate the correct CR3 value.
		 *
		 * @param target_pid The PID of the target process.
		 * @return The CR3 address (page directory base address) if found, otherwise 0.
		 */
		uint64_t get_cr3(uint64_t target_pid) {
			// Validate PID
			if (target_pid == 0 || target_pid > 0xFFFFFFFF) {
				return 0;
			}
			static uint64_t cached_pid = 0;
			static uint64_t cached_cr3 = 0;

			if (cached_pid == target_pid && cached_cr3 != 0) {
				return cached_cr3;
			}
			// --------------------------------------------------------

			uint64_t checked_pfns = 0;
			const uint64_t MAX_PFNS_TO_CHECK = 100000000; // Prevent infinite loops

			for (uint32_t mem_range_count = 0; mem_range_count < 512; mem_range_count++) {

				if (!memory_ranges[mem_range_count].BaseAddress.QuadPart &&
					!memory_ranges[mem_range_count].NumberOfBytes.QuadPart)
					break;

				uint64_t start_pfn = memory_ranges[mem_range_count].BaseAddress.QuadPart >> 12;
				uint64_t end_pfn = start_pfn + (memory_ranges[mem_range_count].NumberOfBytes.QuadPart >> 12);

				// Validate PFN range
				if (start_pfn >= end_pfn || end_pfn > 0xFFFFFFFFF) {
					continue;
				}

				for (uint64_t i = start_pfn; i < end_pfn; i++) {
					if (++checked_pfns > MAX_PFNS_TO_CHECK) {
						return 0;
					}

					_MMPFN cur_mmpfn;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&cur_mmpfn, (void*)&mm_pfn_database[i], sizeof(_MMPFN), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					if (!cur_mmpfn.flags || cur_mmpfn.flags == 1 || cur_mmpfn.pte_address != cr3_ptebase)
						continue;

					uint64_t decrypted_eprocess = g_MiGetPageTablePfnBuddyRaw
						? g_MiGetPageTablePfnBuddyRaw(cur_mmpfn)
						: ((cur_mmpfn.flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;

					uint64_t dirbase = i << 12;
					uint64_t pid = 0;

					uint32_t active_threads;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&active_threads, (void*)(decrypted_eprocess + ACTIVE_THREADS), sizeof(active_threads), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					// Validate active threads count is reasonable
					if (!active_threads || active_threads > 10000)
						continue;

					if (physmem::runtime::copy_memory_to_constructed_cr3(&pid, (void*)(decrypted_eprocess + PID_OFFSET), sizeof(pid), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					if (pid != target_pid)
						continue;
					cached_pid = target_pid;
					cached_cr3 = dirbase;
					return dirbase;
				}
			}

			return 0;
		}

		/**
		 * @brief Retrieves the PID (Process ID) of a process based on its image name.
		 *
		 * This function scans through the system's memory ranges to locate processes that match
		 * the specified image name. It decrypts the eProcess structure, checks for active threads,
		 * and matches the image name with the target process name. Once found, the PID of the process
		 * is returned.
		 *
		 * @param target_process_name The name of the target process to find.
		 * @return The PID of the matching process if found, otherwise 0.
		 */
		uint64_t get_pid(const char* target_process_name) {
		// Validate input
		if (!target_process_name || strlen(target_process_name) == 0) {
			return 0;
		}

		uint64_t checked_pfns = 0;
		const uint64_t MAX_PFNS_TO_CHECK = 100000000; // Prevent infinite loops

			for (uint32_t mem_range_count = 0; mem_range_count < 512; mem_range_count++) {

				if (!memory_ranges[mem_range_count].BaseAddress.QuadPart &&
					!memory_ranges[mem_range_count].NumberOfBytes.QuadPart)
					break;

				uint64_t start_pfn = memory_ranges[mem_range_count].BaseAddress.QuadPart >> 12;
				uint64_t end_pfn = start_pfn + (memory_ranges[mem_range_count].NumberOfBytes.QuadPart >> 12);

			// Validate PFN range
			if (start_pfn >= end_pfn || end_pfn > 0xFFFFFFFFF) {
				continue;
			}

				for (uint64_t i = start_pfn; i < end_pfn; i++) {
				// Safety check: prevent scanning too many PFNs
				if (++checked_pfns > MAX_PFNS_TO_CHECK) {
					logging::root_printf("PFN scan limit reached for process %s", target_process_name);
					return 0;
				}

					_MMPFN cur_mmpfn;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&cur_mmpfn, (void*)&mm_pfn_database[i], sizeof(_MMPFN), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					if (!cur_mmpfn.flags || cur_mmpfn.flags == 1 || cur_mmpfn.pte_address != cr3_ptebase)
						continue;

					uint64_t decrypted_eprocess = g_MiGetPageTablePfnBuddyRaw
						? g_MiGetPageTablePfnBuddyRaw(cur_mmpfn)
						: ((cur_mmpfn.flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;

					uint64_t dirbase = i << 12;

					uint32_t active_threads;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&active_threads, (void*)(decrypted_eprocess + ACTIVE_THREADS), sizeof(active_threads), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
				
				// Validate active threads count is reasonable
				if (!active_threads || active_threads > 10000)
						continue;

				char image_name[IMAGE_NAME_LENGTH + 1];
				memset(image_name, 0, sizeof(image_name));
				if (physmem::runtime::copy_memory_to_constructed_cr3(&image_name, (void*)(decrypted_eprocess + IMAGE_NAME_OFFSET), IMAGE_NAME_LENGTH, physmem::util::get_system_cr3().flags)
					!= status_success)
					continue;
				if (_stricmp(image_name, target_process_name) != 0) {
					if (!strstr(target_process_name, image_name) && !strstr(image_name, target_process_name)) {
						continue;
					}
				}

					uint64_t pid = 0;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&pid, (void*)(decrypted_eprocess + PID_OFFSET), sizeof(pid), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
				if (!pid || pid > 0xFFFFFFFF)
					continue;

					uint64_t peb;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&peb, (void*)(decrypted_eprocess + PEB_OFFSET), sizeof(peb), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
				
				// Validate PEB is in user range
				if (peb == 0 || peb >= 0x7FFFFFFFFFFF) {
					continue;
				}

					PEB_LDR_DATA* pldr;
					project_status status = physmem::runtime::copy_memory_to_constructed_cr3(&pldr, (void*)(peb + LDR_DATA_OFFSET), sizeof(PEB_LDR_DATA*), dirbase);
				if (status != status_success || !pldr)
						continue;

					PEB_LDR_DATA ldr_data;
					status = physmem::runtime::copy_memory_to_constructed_cr3(&ldr_data, pldr, sizeof(PEB_LDR_DATA), dirbase);
					if (status != status_success)
						continue;

					LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
					LIST_ENTRY* next_link = remote_flink;

				if (!next_link) {
					continue;
				}

				uint32_t module_iterations = 0;
				const uint32_t MAX_MODULE_ITERATIONS = 1000; // Prevent infinite loops

				do {
					// Safety check: prevent infinite loops
					if (++module_iterations > MAX_MODULE_ITERATIONS) {
						break;
					}

						LDR_DATA_TABLE_ENTRY entry;
						status = physmem::runtime::copy_memory_to_constructed_cr3(&entry, next_link, sizeof(LDR_DATA_TABLE_ENTRY), dirbase);
						if (status != status_success)
							break;

						wchar_t dll_name_buffer[MAX_PATH] = { 0 };
						char char_dll_name_buffer[MAX_PATH] = { 0 };

					// Validate length is reasonable
					if (entry.BaseDllName.Length == 0 || entry.BaseDllName.Length > MAX_PATH * sizeof(wchar_t)) {
						next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
						continue;
					}

						status = physmem::runtime::copy_memory_to_constructed_cr3(&dll_name_buffer, entry.BaseDllName.Buffer, entry.BaseDllName.Length, dirbase);
					if (status != status_success) {
						next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
							continue;
					}

						for (uint64_t j = 0; j < entry.BaseDllName.Length / sizeof(wchar_t) && j < MAX_PATH - 1; j++)
							char_dll_name_buffer[j] = (char)dll_name_buffer[j];

						char_dll_name_buffer[entry.BaseDllName.Length / sizeof(wchar_t)] = '\0';

						if (strstr(target_process_name, char_dll_name_buffer)) {
							return pid;
						}

						next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
					} while (next_link && next_link != remote_flink);
				}
			}

			logging::root_printf("Failed to find process %s", target_process_name);

			return 0;
		}
	};

	namespace peb {
		/*
			Core API'S
		*/
		/**
		 * @brief Retrieves the LDR_DATA_TABLE_ENTRY for a specific module in a target process.
		 *
		 * This function scans through the system memory to locate a process with the specified `target_pid`.
		 * It then navigates through the Process Environment Block (PEB) and its loaded modules list to find a
		 * module whose name matches `module_name`. If a match is found, the corresponding `LDR_DATA_TABLE_ENTRY`
		 * is returned to the caller.
		 *
		 * @param target_pid The PID of the target process whose loaded modules are to be searched.
		 * @param module_name The name of the module to search for in the target process.
		 * @param module_entry A pointer to the `LDR_DATA_TABLE_ENTRY` where the matching entry will be copied if found.
		 * @return project_status status indicating the success or failure of the operation.
		 *         Returns `status_success` on success, `status_failure` otherwise.
		 */
		project_status get_ldr_data_table_entry(uint64_t target_pid, char* module_name, LDR_DATA_TABLE_ENTRY* module_entry) {
		// Validate input
		if (!module_name || !module_entry || target_pid == 0 || target_pid > 0xFFFFFFFF) {
			return status_invalid_parameter;
		}

		uint64_t checked_pfns = 0;
		const uint64_t MAX_PFNS_TO_CHECK = 100000000;

			for (uint32_t mem_range_count = 0; mem_range_count < 512; mem_range_count++) {

				if (!memory_ranges[mem_range_count].BaseAddress.QuadPart &&
					!memory_ranges[mem_range_count].NumberOfBytes.QuadPart)
					break;

				uint64_t start_pfn = memory_ranges[mem_range_count].BaseAddress.QuadPart >> 12;
				uint64_t end_pfn = start_pfn + (memory_ranges[mem_range_count].NumberOfBytes.QuadPart >> 12);

			// Validate PFN range
			if (start_pfn >= end_pfn || end_pfn > 0xFFFFFFFFF) {
				continue;
			}

				for (uint64_t i = start_pfn; i < end_pfn; i++) {
				// Safety check
				if (++checked_pfns > MAX_PFNS_TO_CHECK) {
					logging::root_printf("PFN scan limit reached for module %s in process %p", module_name, target_pid);
					return status_failure;
				}

					_MMPFN cur_mmpfn;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&cur_mmpfn, (void*)&mm_pfn_database[i], sizeof(_MMPFN), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					if (!cur_mmpfn.flags || cur_mmpfn.flags == 1 || cur_mmpfn.pte_address != cr3_ptebase)
						continue;

					uint64_t decrypted_eprocess = g_MiGetPageTablePfnBuddyRaw
						? g_MiGetPageTablePfnBuddyRaw(cur_mmpfn)
						: ((cur_mmpfn.flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;

					uint64_t dirbase = i << 12;

					uint32_t active_threads;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&active_threads, (void*)(decrypted_eprocess + ACTIVE_THREADS), sizeof(active_threads), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
				if (!active_threads || active_threads > 10000)
						continue;

					uint64_t pid = 0;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&pid, (void*)(decrypted_eprocess + PID_OFFSET), sizeof(pid), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (pid != target_pid)
						continue;

					uint64_t peb;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&peb, (void*)(decrypted_eprocess + PEB_OFFSET), sizeof(peb), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
				
				// Validate PEB
				if (peb == 0 || peb >= 0x7FFFFFFFFFFF) {
					continue;
				}

					PEB_LDR_DATA* pldr;
					project_status status = physmem::runtime::copy_memory_to_constructed_cr3(&pldr, (void*)(peb + LDR_DATA_OFFSET), sizeof(PEB_LDR_DATA*), dirbase);
				if (status != status_success || !pldr)
						continue;

					PEB_LDR_DATA ldr_data;
					status = physmem::runtime::copy_memory_to_constructed_cr3(&ldr_data, pldr, sizeof(PEB_LDR_DATA), dirbase);
					if (status != status_success)
						continue;

					LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
					LIST_ENTRY* next_link = remote_flink;

				if (!next_link) {
					continue;
				}

				uint32_t module_iterations = 0;
				const uint32_t MAX_MODULE_ITERATIONS = 1000;

				do {
					// Safety check
					if (++module_iterations > MAX_MODULE_ITERATIONS) {
						break;
					}

						LDR_DATA_TABLE_ENTRY entry;
						status = physmem::runtime::copy_memory_to_constructed_cr3(&entry, next_link, sizeof(LDR_DATA_TABLE_ENTRY), dirbase);
						if (status != status_success)
							break;

						wchar_t dll_name_buffer[MAX_PATH] = { 0 };
						char char_dll_name_buffer[MAX_PATH] = { 0 };

					// Validate length
					if (entry.BaseDllName.Length == 0 || entry.BaseDllName.Length > MAX_PATH * sizeof(wchar_t)) {
						next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
						continue;
					}

						status = physmem::runtime::copy_memory_to_constructed_cr3(&dll_name_buffer, entry.BaseDllName.Buffer, entry.BaseDllName.Length, dirbase);
					if (status != status_success) {
						next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
							continue;
					}

						for (uint64_t j = 0; j < entry.BaseDllName.Length / sizeof(wchar_t) && j < MAX_PATH - 1; j++)
							char_dll_name_buffer[j] = (char)dll_name_buffer[j];

						char_dll_name_buffer[entry.BaseDllName.Length / sizeof(wchar_t)] = '\0';

						if (strstr(module_name, char_dll_name_buffer)) {
							memcpy(module_entry, &entry, sizeof(LDR_DATA_TABLE_ENTRY));
						return status_success;
						}

						next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
					} while (next_link && next_link != remote_flink);
				}
			}

			logging::root_printf("Failed to find module %s in process %p", module_name, target_pid);

			return status_failure;
		}

		/*
			Exposed API'S
		*/
		/**
		 * @brief Retrieves information about loaded modules in a specific process by PID.
		 *
		 * This function iterates through the memory ranges of the system and checks the loaded modules
		 * for a process with a given PID. It collects the base address, size, and name of each module
		 * and stores this information in the provided `info_array`.
		 *
		 * @param target_pid The PID of the target process whose module information needs to be retrieved.
		 * @param info_array An array of `module_info_t` structures where the module information will be stored.
		 * @param proc_cr3 The CR3 of the target process used to access the process's page tables for memory access.
		 * @return project_status Returns `status_success` if module information is successfully retrieved,
		 *                        otherwise returns `status_failure`.
		 */
		project_status get_data_table_entry_info(uint64_t target_pid, module_info_t* info_array, uint64_t proc_cr3) {
			if (!info_array || target_pid == 0 || target_pid > 0xFFFFFFFF) {
				return status_invalid_parameter;
			}

			uint64_t curr_info_entry = (uint64_t)info_array;
			uint64_t checked_pfns = 0;
			const uint64_t MAX_PFNS_TO_CHECK = 100000000;

			for (uint32_t mem_range_count = 0; mem_range_count < 512; mem_range_count++) {

				if (!memory_ranges[mem_range_count].BaseAddress.QuadPart &&
					!memory_ranges[mem_range_count].NumberOfBytes.QuadPart)
					break;

				uint64_t start_pfn = memory_ranges[mem_range_count].BaseAddress.QuadPart >> 12;
				uint64_t end_pfn = start_pfn + (memory_ranges[mem_range_count].NumberOfBytes.QuadPart >> 12);

				// Validate PFN range
				if (start_pfn >= end_pfn || end_pfn > 0xFFFFFFFFF) {
					continue;
				}

				for (uint64_t i = start_pfn; i < end_pfn; i++) {
					// Safety check
					if (++checked_pfns > MAX_PFNS_TO_CHECK) {
						logging::root_printf("PFN scan limit reached in get_data_table_entry_info for PID %p", target_pid);
						return status_failure;
					}

					_MMPFN cur_mmpfn;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&cur_mmpfn, (void*)&mm_pfn_database[i], sizeof(_MMPFN), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					if (!cur_mmpfn.flags || cur_mmpfn.flags == 1 || cur_mmpfn.pte_address != cr3_ptebase)
						continue;

					uint64_t decrypted_eprocess = g_MiGetPageTablePfnBuddyRaw
						? g_MiGetPageTablePfnBuddyRaw(cur_mmpfn)
						: ((cur_mmpfn.flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;

					uint64_t dirbase = i << 12;

					uint32_t active_threads;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&active_threads, (void*)(decrypted_eprocess + ACTIVE_THREADS), sizeof(active_threads), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (!active_threads || active_threads > 10000)
						continue;

					uint64_t pid = 0;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&pid, (void*)(decrypted_eprocess + PID_OFFSET), sizeof(pid), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (pid != target_pid)
						continue;

					uint64_t peb;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&peb, (void*)(decrypted_eprocess + PEB_OFFSET), sizeof(peb), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					
					// Validate PEB
					if (peb == 0 || peb >= 0x7FFFFFFFFFFF) {
						continue;
					}

					PEB_LDR_DATA* pldr;
					project_status status = physmem::runtime::copy_memory_to_constructed_cr3(&pldr, (void*)(peb + LDR_DATA_OFFSET), sizeof(PEB_LDR_DATA*), dirbase);
					if (status != status_success || !pldr)
						continue;

					PEB_LDR_DATA ldr_data;
					status = physmem::runtime::copy_memory_to_constructed_cr3(&ldr_data, pldr, sizeof(PEB_LDR_DATA), dirbase);
					if (status != status_success)
						continue;

					LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
					LIST_ENTRY* next_link = remote_flink;
					
					if (!next_link) continue;

					uint32_t module_iterations = 0;
					const uint32_t MAX_MODULE_ITERATIONS = 1000;

					do {
						// Safety check
						if (++module_iterations > MAX_MODULE_ITERATIONS) {
							break;
						}

						LDR_DATA_TABLE_ENTRY entry;
						status = physmem::runtime::copy_memory_to_constructed_cr3(&entry, next_link, sizeof(LDR_DATA_TABLE_ENTRY), dirbase);
						if (status != status_success)
							break;

						wchar_t dll_name_buffer[MAX_PATH] = { 0 };
						char char_dll_name_buffer[MAX_PATH] = { 0 };

						// Validate length
						if (entry.BaseDllName.Length == 0 || entry.BaseDllName.Length > MAX_PATH * sizeof(wchar_t)) {
							next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
							continue;
						}

						status = physmem::runtime::copy_memory_to_constructed_cr3(&dll_name_buffer, entry.BaseDllName.Buffer, entry.BaseDllName.Length, dirbase);
						if (status != status_success) {
							next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
							continue;
						}

						for (uint64_t j = 0; j < entry.BaseDllName.Length / sizeof(wchar_t) && j < MAX_PATH - 1; j++)
							char_dll_name_buffer[j] = (char)dll_name_buffer[j];

						char_dll_name_buffer[entry.BaseDllName.Length / sizeof(wchar_t)] = '\0';

						module_info_t info = { 0 };
						info.base = (uint64_t)entry.DllBase;
						info.size = entry.SizeOfImage;
						memcpy(&info.name, &char_dll_name_buffer, min(entry.BaseDllName.Length / sizeof(wchar_t), MAX_PATH - 1));

						status = physmem::runtime::copy_memory_from_constructed_cr3((void*)curr_info_entry, &info, sizeof(module_info_t), proc_cr3);
						if (status != status_success) {
							next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
							continue;
						}

						curr_info_entry += sizeof(module_info_t);
						next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
					} while (next_link && next_link != remote_flink);

					return status;
				}
			}

			logging::root_printf("Failed to find data table entry info in process %p", target_pid);

			return status_failure;
		}
		/**
		 * @brief Retrieves the count of loaded modules for a specific process by its PID.
		 *
		 * This function scans the memory ranges to locate the specified process using its PID and then counts
		 * the number of modules loaded in the process's address space. The count is obtained by iterating
		 * through the `PEB_LDR_DATA` structure and counting the entries in the load order list of modules.
		 *
		 * @param target_pid The PID of the target process whose loaded modules are to be counted.
		 * @return uint64_t The number of modules loaded in the target process, or `status_failure` if the process
		 *                  or its modules could not be located.
		 */
		uint64_t get_data_table_entry_count(uint64_t target_pid) {
			// Validate PID
			if (target_pid == 0 || target_pid > 0xFFFFFFFF) {
				return 0;
			}

			uint64_t checked_pfns = 0;
			const uint64_t MAX_PFNS_TO_CHECK = 100000000;

			for (uint32_t mem_range_count = 0; mem_range_count < 512; mem_range_count++) {

				if (!memory_ranges[mem_range_count].BaseAddress.QuadPart &&
					!memory_ranges[mem_range_count].NumberOfBytes.QuadPart)
					break;

				uint64_t start_pfn = memory_ranges[mem_range_count].BaseAddress.QuadPart >> 12;
				uint64_t end_pfn = start_pfn + (memory_ranges[mem_range_count].NumberOfBytes.QuadPart >> 12);

				// Validate PFN range
				if (start_pfn >= end_pfn || end_pfn > 0xFFFFFFFFF) {
					continue;
				}

				for (uint64_t i = start_pfn; i < end_pfn; i++) {
					// Safety check
					if (++checked_pfns > MAX_PFNS_TO_CHECK) {
						logging::root_printf("PFN scan limit reached in get_data_table_entry_count for PID %p", target_pid);
						return 0;
					}

					_MMPFN cur_mmpfn;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&cur_mmpfn, (void*)&mm_pfn_database[i], sizeof(_MMPFN), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;

					if (!cur_mmpfn.flags || cur_mmpfn.flags == 1 || cur_mmpfn.pte_address != cr3_ptebase)
						continue;

					uint64_t decrypted_eprocess = g_MiGetPageTablePfnBuddyRaw
						? g_MiGetPageTablePfnBuddyRaw(cur_mmpfn)
						: ((cur_mmpfn.flags | 0xF000000000000000) >> 0xd) | 0xFFFF000000000000;

					uint64_t dirbase = i << 12;

					uint32_t active_threads;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&active_threads, (void*)(decrypted_eprocess + ACTIVE_THREADS), sizeof(active_threads), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (!active_threads || active_threads > 10000)
						continue;

					uint64_t pid = 0;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&pid, (void*)(decrypted_eprocess + PID_OFFSET), sizeof(pid), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					if (pid != target_pid)
						continue;

					uint64_t peb;
					if (physmem::runtime::copy_memory_to_constructed_cr3(&peb, (void*)(decrypted_eprocess + PEB_OFFSET), sizeof(peb), physmem::util::get_system_cr3().flags)
						!= status_success)
						continue;
					
					// Validate PEB
					if (peb == 0 || peb >= 0x7FFFFFFFFFFF) {
						continue;
					}

					PEB_LDR_DATA* pldr;
					project_status status = physmem::runtime::copy_memory_to_constructed_cr3(&pldr, (void*)(peb + LDR_DATA_OFFSET), sizeof(PEB_LDR_DATA*), dirbase);
					if (status != status_success || !pldr)
						continue;

					PEB_LDR_DATA ldr_data;
					status = physmem::runtime::copy_memory_to_constructed_cr3(&ldr_data, pldr, sizeof(PEB_LDR_DATA), dirbase);
					if (status != status_success)
						continue;

					LIST_ENTRY* remote_flink = ldr_data.InLoadOrderModuleList.Flink;
					LIST_ENTRY* next_link = remote_flink;
					
					if (!next_link) continue;

					uint64_t module_count = 0;
					uint32_t module_iterations = 0;
					const uint32_t MAX_MODULE_ITERATIONS = 1000;

					do {
						// Safety check
						if (++module_iterations > MAX_MODULE_ITERATIONS) {
							break;
						}

						LDR_DATA_TABLE_ENTRY entry;
						status = physmem::runtime::copy_memory_to_constructed_cr3(&entry, next_link, sizeof(LDR_DATA_TABLE_ENTRY), dirbase);
						if (status != status_success)
						{
							return module_count;
						}

						module_count++;
						next_link = (LIST_ENTRY*)entry.InLoadOrderLinks.Flink;
					} while (next_link && next_link != remote_flink);

					return module_count;
				}
			}

			logging::root_printf("Failed to find module count in process %p", target_pid);

			return status_failure;
		}

		/**
		 * @brief Retrieves the base address of a specified module in the target process.
		 *
		 * This function fetches the base address of a loaded module in the target process. It uses the
		 * process's PID and the module name to locate the appropriate `LDR_DATA_TABLE_ENTRY`, from which
		 * the base address of the module is returned.
		 *
		 * @param target_pid The PID of the target process whose module's base address is to be retrieved.
		 * @param module_name The name of the module whose base address is to be found.
		 * @return uint64_t The base address of the specified module, or 0 if the module could not be found.
		 */
		uint64_t get_module_base(uint64_t target_pid, char* module_name) {
			LDR_DATA_TABLE_ENTRY data_table_entry;

			project_status status = get_ldr_data_table_entry(target_pid, module_name, &data_table_entry);
			if (status != status_success)
				return 0;

			logging::root_printf("%s module base %p", data_table_entry.BaseDllName, data_table_entry.DllBase);

			return (uint64_t)data_table_entry.DllBase;
		}

		/**
		 * @brief Retrieves the size of a specified module in the target process.
		 *
		 * This function fetches the size of a loaded module in the target process. It uses the process's
		 * PID and the module name to locate the appropriate `LDR_DATA_TABLE_ENTRY`, from which the size of
		 * the module (its image size) is returned.
		 *
		 * @param target_pid The PID of the target process whose module's size is to be retrieved.
		 * @param module_name The name of the module whose size is to be found.
		 * @return uint64_t The size of the specified module, or 0 if the module could not be found.
		 */
		uint64_t get_module_size(uint64_t target_pid, char* module_name) {
			LDR_DATA_TABLE_ENTRY data_table_entry;

			project_status status = get_ldr_data_table_entry(target_pid, module_name, &data_table_entry);
			if (status != status_success)
				return 0;

			logging::root_printf("%s module size %p", data_table_entry.BaseDllName, data_table_entry.SizeOfImage);

			return (uint64_t)data_table_entry.SizeOfImage;
		}
	};
};