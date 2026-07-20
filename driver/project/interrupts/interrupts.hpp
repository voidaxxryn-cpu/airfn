#pragma once

#include "../project_includes.hpp"
#include "interrupt_structs.hpp"
#include "../windows_structs.hpp"
#include <ntimage.h>

// External declarations for assembly functions and accessors
extern "C" uint16_t __readcs(void); /**< Reads the current code segment register */
extern "C" void _cli(void); /**< Clears interrupts (disables interrupts) */
extern "C" void _sti(void); /**< Sets the interrupt flag (enables interrupts) */
extern "C" void __swapgs(void); /**< Switches the GS segment register */
extern "C" KPCR* __getpcr(void); /**< Retrieves the current PCR (Processor Control Region) */

/**
 * @brief Nonmaskable Interrupt (NMI) handler function.
 *
 * This is the entry point for handling nonmaskable interrupts (NMIs).
 * It is typically used to handle critical hardware exceptions or other unmasked
 * interrupts that cannot be ignored by the processor.
 */
extern "C" void asm_nmi_handler(void);

namespace interrupts {

    /**
     * @brief Initializes the interrupt system.
     *
     * This function sets up the interrupt descriptor table (IDT), initializes necessary
     * interrupt handlers, and prepares the system to handle interrupts.
     *
     * @return project_status The status of the initialization.
     *                        Returns success or failure based on the initialization outcome.
     */
    project_status init_interrupts();

    /**
     * @brief Checks if the interrupt system is initialized.
     *
     * This function returns whether the interrupt system has been properly initialized
     * and is ready to handle interrupts.
     *
     * @return bool True if the interrupt system is initialized, false otherwise.
     */
    bool is_initialized(void);

    /**
     * @brief Retrieves the address of the Windows NMI handler.
     *
     * This function returns a pointer to the handler for Nonmaskable Interrupts (NMI)
     * specifically designed for Windows environments.
     *
     * @return void* A pointer to the NMI handler.
     */
    void* get_windows_nmi_handler(void);

    /**
     * @brief Retrieves the constructed IDT pointer.
     *
     * This function returns a 64-bit segment descriptor representing the pointer to
     * the Interrupt Descriptor Table (IDT). The IDT contains entries that map interrupt
     * vectors to their corresponding interrupt service routines (ISRs).
     *
     * @return segment_descriptor_register_64 The segment descriptor for the IDT.
     */
    segment_descriptor_register_64 get_constructed_idt_ptr(void);
};
