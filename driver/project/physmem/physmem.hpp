/**
 * @file physmem.hpp
 * @brief Header file for physical memory management, including initialization, memory remapping, translation, and paging manipulation functions.
 *
 * This header file contains declarations for the functions and utilities that are responsible for managing physical memory in the system.
 * The `physmem` namespace encapsulates functionalities related to physical memory initialization, memory remapping, memory translation,
 * paging manipulations, and memory copying.
 */

#pragma once

#include "../project_includes.hpp"
#include "../windows_structs.hpp"

#include "physmem_structs.hpp"
#include "page_table_helpers.hpp"

namespace physmem {

    /**
     * @brief Initialization functions for physical memory management.
     *
     * This section defines the functions used to initialize the physical memory management system and check whether it is initialized.
     */
     // Initialization functions

     /**
      * @brief Initializes the physical memory system.
      *
      * This function initializes the memory system by setting up the page tables and other memory structures required for memory
      * remapping and address translation.
      *
      * @return A `project_status` indicating success or failure.
      */
    project_status init_physmem(void);

    /**
     * @brief Checks if the physical memory system has been initialized.
     *
     * This function returns whether the physical memory management system has been successfully initialized and is ready for
     * memory management operations.
     *
     * @return A boolean value: true if initialized, false otherwise.
     */
    bool is_initialized(void);

    /**
     * @brief Utility functions for accessing CR3 values.
     *
     * These functions are used to retrieve the CR3 values, both for the constructed CR3 (after remapping) and the system's current CR3.
     */
    namespace util {

        /**
         * @brief Gets the constructed CR3 value.
         *
         * This function retrieves the constructed CR3 value, which represents the physical memory layout after remapping.
         *
         * @return The constructed CR3 value.
         */
        cr3 get_constructed_cr3(void);

        /**
         * @brief Gets the system's current CR3 value.
         *
         * This function retrieves the current CR3 value used by the system for address translation.
         *
         * @return The system's CR3 value.
         */
        cr3 get_system_cr3(void);
    };

    /**
     * @brief Runtime functions for memory translation and copying.
     *
     * This section provides functions for translating virtual memory addresses to physical addresses, as well as copying
     * memory between virtual and physical addresses.
     */
    namespace runtime {

        /**
         * @brief Translates a virtual address to a physical address.
         *
         * This function translates a given virtual address in a target CR3 context to a corresponding physical address.
         * Optionally, the function can return the remaining bytes if requested.
         *
         * @param outside_target_cr3 The CR3 value of the target address space.
         * @param virtual_address The virtual address to be translated.
         * @param physical_address The resulting physical address after translation.
         * @param remaining_bytes The number of remaining bytes, if any.
         * @return A `project_status` indicating success or failure.
         */
        project_status translate_to_physical_address(uint64_t outside_target_cr3, void* virtual_address, uint64_t& physical_address, uint64_t* remaining_bytes = 0);

        /**
         * @brief Copies physical memory from one location to another.
         *
         * This function copies a range of memory from one physical address to another.
         *
         * @param dst_physical The destination physical address.
         * @param src_physical The source physical address.
         * @param size The size of the memory to be copied.
         */
        void copy_physical_memory(uint64_t dst_physical, uint64_t src_physical, uint64_t size);

        /**
         * @brief Copies virtual memory from one address space to another.
         *
         * This function copies memory between two virtual addresses, taking the CR3 values of the source and destination address spaces into account.
         *
         * @param dst The destination address.
         * @param src The source address.
         * @param size The size of the memory to be copied.
         * @param dst_cr3 The CR3 value for the destination address space.
         * @param src_cr3 The CR3 value for the source address space.
         * @return A `project_status` indicating success or failure.
         */
        project_status copy_virtual_memory(void* dst, void* src, uint64_t size, uint64_t dst_cr3, uint64_t src_cr3);

        /**
         * @brief Copies memory from a virtual address in the constructed CR3 address space.
         *
         * This function copies memory from a virtual address to a destination address in the constructed CR3 space.
         *
         * @param dst The destination address.
         * @param src The source address.
         * @param size The size of the memory to be copied.
         * @param src_cr3 The CR3 value for the source address space.
         * @return A `project_status` indicating success or failure.
         */
        project_status copy_memory_to_constructed_cr3(void* dst, void* src, uint64_t size, uint64_t src_cr3);

        /**
         * @brief Copies memory to a virtual address in the constructed CR3 address space.
         *
         * This function copies memory from a source address to a destination address in the constructed CR3 space.
         *
         * @param dst The destination address.
         * @param src The source address.
         * @param size The size of the memory to be copied.
         * @param dst_cr3 The CR3 value for the destination address space.
         * @return A `project_status` indicating success or failure.
         */
        project_status copy_memory_from_constructed_cr3(void* dst, void* src, uint64_t size, uint64_t dst_cr3);
    };

    /**
     * @brief Functions for remapping memory.
     *
     * This section contains functions that ensure memory is properly mapped and allow overwriting virtual address mappings.
     */
    namespace remapping {

        /**
         * @brief Ensures that memory is mapped for a specified address range.
         *
         * This function verifies that the memory range starting at `target_address` is correctly mapped in the specified
         * CR3 address space.
         *
         * @param target_address The target virtual address to be mapped.
         * @param size The size of the memory range.
         * @param mem_cr3_u64 The CR3 value for the target address space.
         * @return A `project_status` indicating success or failure.
         */
        project_status ensure_memory_mapping_for_range(void* target_address, uint64_t size, uint64_t mem_cr3_u64);

        /**
         * @brief Overwrites the mapping of a virtual address with a new memory mapping.
         *
         * This function replaces the current mapping for a virtual address with a new memory mapping. The function uses
         * the provided source and destination CR3 values to perform the operation.
         *
         * @param target_address The virtual address to be overwritten.
         * @param new_memory The new memory to be mapped.
         * @param target_address_cr3_u64 The CR3 value for the target address space.
         * @param new_mem_cr3_u64 The CR3 value for the new memory address space.
         * @return A `project_status` indicating success or failure.
         */
        project_status overwrite_virtual_address_mapping(void* target_address, void* new_memory, uint64_t target_address_cr3_u64, uint64_t new_mem_cr3_u64);
    };

    /**
     * @brief Functions for manipulating page tables.
     *
     * This section contains functions used to manipulate and unmap memory ranges in the paging system.
     */
    namespace paging_manipulation {

        /**
         * @brief Unmaps a memory range in the page table.
         *
         * This function unmaps a specified range of memory from the page table, effectively invalidating the mapping for
         * that range.
         *
         * @param memory The memory to unmap.
         * @param mem_cr3_u64 The CR3 value for the address space.
         * @param size The size of the memory range to unmap.
         * @return A `project_status` indicating success or failure.
         */
        project_status win_unmap_memory_range(void* memory, uint64_t mem_cr3_u64, uint64_t size);
    };

    /**
     * @brief Testing functions for memory operations.
     *
     * This section contains test functions used to verify the correctness of memory operations, such as copying.
     */
    namespace testing {

        /**
         * @brief Tests memory copying functionality.
         *
         * This function runs a test to verify that memory copying works correctly. It performs memory copy operations and
         * checks if the data is correctly transferred.
         *
         * @return A boolean value indicating whether the memory copy test passed.
         */
        bool memory_copy_test1(void);
    };
};
