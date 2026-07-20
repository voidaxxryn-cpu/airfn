#pragma once
#include "../project_includes.hpp"
#include "physmem_structs.hpp"

namespace pt_helpers {
    /**
     * @brief Checks if the provided index is valid (less than 512).
     *
     * This helper function ensures that the index is within the valid range for page table entries.
     *
     * @param index The index to check.
     * @return true if the index is valid, false otherwise.
     */
    inline bool is_index_valid(uint64_t index) {
        return index < 512;
    }
    /**
     * @brief Finds the first free entry in the PML4E (Page Map Level 4 Entry) table.
     *
     * Searches through the PML4E table to find the first unoccupied entry.
     *
     * @param pml4e_table The PML4E table to search.
     * @return The index of the first free entry, or MAXULONG32 if none are free.
     */
    inline uint32_t find_free_pml4e_index(pml4e_64* pml4e_table) {
        for (uint32_t i = 0; i < 512; i++) {
            if (!pml4e_table[i].present) {
                return i;
            }
        }

        return MAXULONG32;
    }
    /**
     * @brief Finds the first free entry in the PDPT (Page Directory Pointer Table) table.
     *
     * Searches through the PDPT table to find the first unoccupied entry.
     *
     * @param pdpte_table The PDPT table to search.
     * @return The index of the first free entry, or MAXULONG32 if none are free.
     */
    inline uint32_t find_free_pdpt_index(pdpte_64* pdpte_table) {
        for (uint32_t i = 0; i < 512; i++) {
            if (!pdpte_table[i].present) {
                return i;
            }
        }

        return MAXULONG32;
    }
    /**
     * @brief Finds the first free entry in the PDE (Page Directory Entry) table.
     *
     * Searches through the PDE table to find the first unoccupied entry.
     *
     * @param pde_table The PDE table to search.
     * @return The index of the first free entry, or MAXULONG32 if none are free.
     */
    inline uint32_t find_free_pd_index(pde_64* pde_table) {
        for (uint32_t i = 0; i < 512; i++) {
            if (!pde_table[i].present) {
                return i;
            }
        }

        return MAXULONG32;
    }
    /**
     * @brief Finds the first free entry in the PTE (Page Table Entry) table.
     *
     * Searches through the PTE table to find the first unoccupied entry.
     *
     * @param pte_table The PTE table to search.
     * @return The index of the first free entry, or MAXULONG32 if none are free.
     */
    inline uint32_t find_free_pt_index(pte_64* pte_table) {
        for (uint32_t i = 0; i < 512; i++) {
            if (!pte_table[i].present) {
                return i;
            }
        }

        return MAXULONG32;
    }
};

namespace pt_manager {
    // Allocation helpers
    /**
     * @brief Retrieves the first free PDPT table from the remapping tables.
     *
     * Searches for the first free PDPT table in the remapping tables and marks it as occupied.
     *
     * @param table The remapping tables to search.
     * @return A pointer to the free PDPT table, or nullptr if none is available.
     */
    inline pdpte_64* get_free_pdpt_table(remapping_tables_t* table) {
        for (uint32_t i = 0; i < REMAPPING_TABLE_COUNT; i++) {
            if (!table->is_pdpt_table_occupied[i]) {
                table->is_pdpt_table_occupied[i] = true;
                return table->pdpt_table[i];
            }
        }

        return 0;
    }
    /**
     * @brief Retrieves the first free PDE table from the remapping tables.
     *
     * Searches for the first free PDE table in the remapping tables and marks it as occupied.
     *
     * @param table The remapping tables to search.
     * @return A pointer to the free PDE table, or nullptr if none is available.
     */
    inline pde_64* get_free_pd_table(remapping_tables_t* table) {
        for (uint32_t i = 0; i < REMAPPING_TABLE_COUNT; i++) {
            if (!table->is_pd_table_occupied[i]) {
                table->is_pd_table_occupied[i] = true;
                return table->pd_table[i];
            }
        }

        return 0;
    }
    /**
     * @brief Retrieves the first free PTE table from the remapping tables.
     *
     * Searches for the first free PTE table in the remapping tables and marks it as occupied.
     *
     * @param table The remapping tables to search.
     * @return A pointer to the free PTE table, or nullptr if none is available.
     */
    inline pte_64* get_free_pt_table(remapping_tables_t* table) {
        for (uint32_t i = 0; i < REMAPPING_TABLE_COUNT; i++) {
            if (!table->is_pt_table_occupied[i]) {
                table->is_pt_table_occupied[i] = true;
                return table->pt_table[i];
            }
        }

        return 0;
    }

    // Freeing helpers
    /**
     * @brief Frees a PDPT table from the remapping tables.
     *
     * Marks the given PDPT table as free and clears its contents.
     *
     * @param table The remapping tables to update.
     * @param pdpt_table The PDPT table to free.
     */
    inline void free_pdpt_table(remapping_tables_t* table, pdpte_64* pdpt_table) {
        for (uint32_t i = 0; i < REMAPPING_TABLE_COUNT; i++) {
            if (table->pdpt_table[i] == pdpt_table) {
                table->is_pdpt_table_occupied[i] = false;
                memset(pdpt_table, 0, 512 * sizeof(pdpte_64));
                return;
            }
        }
    }
    /**
     * @brief Frees a PDE table from the remapping tables.
     *
     * Marks the given PDE table as free and clears its contents.
     *
     * @param table The remapping tables to update.
     * @param pd_table The PDE table to free.
     */
    inline void free_pd_table(remapping_tables_t* table, pde_64* pd_table) {
        for (uint32_t i = 0; i < REMAPPING_TABLE_COUNT; i++) {
            if (table->pd_table[i] == pd_table) {
                table->is_pd_table_occupied[i] = false;
                memset(pd_table, 0, 512 * sizeof(pde_64));
                return;
            }
        }
    }
    /**
     * @brief Frees a PTE table from the remapping tables.
     *
     * Marks the given PTE table as free and clears its contents.
     *
     * @param table The remapping tables to update.
     * @param pt_table The PTE table to free.
     */
    inline void free_pt_table(remapping_tables_t* table, pte_64* pt_table) {
        for (uint32_t i = 0; i < REMAPPING_TABLE_COUNT; i++) {
            if (table->pt_table[i] == pt_table) {
                table->is_pt_table_occupied[i] = false;
                memset(pt_table, 0, 512 * sizeof(pte_64));
                return;
            }
        }
    }
};