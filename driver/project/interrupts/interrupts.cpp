#include "interrupts.hpp"
#include "../communication/shellcode.hpp"
#include "../physmem/physmem.hpp"

namespace interrupts {
    /*
        Definitions
    */
#define  SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE 0xE /**< The type of the segment descriptor for interrupt gates */

    /*
        Global variables
    */
    bool initialized = false; /**< Flag to track if the interrupt system is initialized */
    segment_descriptor_interrupt_gate_64* constructed_idt_table = 0; /**< Pointer to the interrupt descriptor table (IDT) */
    segment_descriptor_register_64 constructed_idt_ptr = { 0 }; /**< Register holding the IDT base address and limit */
    uint64_t g_windows_nmi_handler; /**< Windows NMI handler address */

    /*
        Utility Functions
    */
    /**
     * @brief Creates an interrupt gate for a specific interrupt.
     *
     * This function constructs a 64-bit segment descriptor for an interrupt gate,
     * which is used to define how the interrupt will be handled by the processor.
     *
     * @param assembly_handler The address of the assembly function to handle the interrupt.
     * @param windows_gate The original gate descriptor from the Windows IDT.
     *
     * @return segment_descriptor_interrupt_gate_64 The constructed interrupt gate descriptor.
     */
    segment_descriptor_interrupt_gate_64 create_interrupt_gate(void* assembly_handler, segment_descriptor_interrupt_gate_64 windows_gate) {
        segment_descriptor_interrupt_gate_64 gate;

        gate.interrupt_stack_table = windows_gate.interrupt_stack_table;
        gate.segment_selector = __readcs(); // Current code segment
        gate.must_be_zero_0 = 0;
        gate.type = SEGMENT_DESCRIPTOR_TYPE_INTERRUPT_GATE; // Interrupt gate type
        gate.must_be_zero_1 = 0;
        gate.descriptor_privilege_level = 0; // DPL of 0 for kernel mode
        gate.present = 1; // Gate is present
        gate.reserved = 0;

        uint64_t offset = (uint64_t)assembly_handler;
        gate.offset_low = (offset >> 0) & 0xFFFF;
        gate.offset_middle = (offset >> 16) & 0xFFFF;
        gate.offset_high = (offset >> 32) & 0xFFFFFFFF;

        return gate;
    }

    /**
     * @brief Retrieves the constructed IDT pointer.
     *
     * This function returns the pointer to the constructed interrupt descriptor table (IDT).
     *
     * @return segment_descriptor_register_64 The IDT register containing the base address and limit.
     */
    segment_descriptor_register_64 get_constructed_idt_ptr(void) {
        return constructed_idt_ptr;
    }

    /*
        Core Interrupt Handling
    */
    /**
     * @brief Nonmaskable Interrupt (NMI) handler called from asm. Do not modify trap frame here.
     * The asm wrapper will chain to our NMI shellcode which handles restoring context and redirection.
     */
    extern "C" void nmi_handler(trap_frame_t* trap_frame) {
        UNREFERENCED_PARAMETER(trap_frame);
        
        // Intentionally minimal: keep state unchanged; asm epilogue will jump to our NMI shellcode.
        _mm_mfence();
    }

    /*
        Initialization functions
    */
    /**
     * @brief Initializes the interrupt handling system.
     *
     * This function sets up the interrupt descriptor table (IDT), including the handling
     * of specific interrupts like the Nonmaskable Interrupt (NMI). It allocates memory
     * for the IDT and sets the necessary segment descriptors.
     *
     * @return project_status The status of the initialization. Returns success or failure.
     */
    project_status init_interrupts() {
        PHYSICAL_ADDRESS max_addr = { 0 };
        max_addr.QuadPart = MAXULONG64;

        // Allocate memory for the IDT table
        constructed_idt_table = (segment_descriptor_interrupt_gate_64*)MmAllocateContiguousMemory(sizeof(segment_descriptor_interrupt_gate_64) * 256, max_addr);
        if (!constructed_idt_table) {
            return status_memory_allocation_failed; // Return failure if allocation fails
        }

        memset(constructed_idt_table, 0, sizeof(segment_descriptor_interrupt_gate_64) * 256);

        segment_descriptor_register_64 idt = { 0 };
        __sidt(&idt); // Load the current IDT into the register

        segment_descriptor_interrupt_gate_64* windows_idt = (segment_descriptor_interrupt_gate_64*)idt.base_address;
        if (!windows_idt)
            return status_failure;

        // Get the address of the NMI handler from the Windows IDT
        g_windows_nmi_handler = (static_cast<uint64_t>(windows_idt[exception_vector::nmi].offset_high) << 32) |
            (static_cast<uint64_t>(windows_idt[exception_vector::nmi].offset_middle) << 16) |
            (windows_idt[exception_vector::nmi].offset_low);

        // Set the custom NMI handler in the constructed IDT
        constructed_idt_table[exception_vector::nmi] = create_interrupt_gate(asm_nmi_handler, windows_idt[exception_vector::nmi]);

        // Set the constructed IDT pointer
        constructed_idt_ptr.base_address = (uint64_t)constructed_idt_table;
        constructed_idt_ptr.limit = (sizeof(segment_descriptor_interrupt_gate_64) * 256) - 1;

        initialized = true; // Mark as initialized

        return status_success; // Return success
    }

    /*
        Exposed API's
    */
    /**
     * @brief Checks if the interrupt system has been initialized.
     *
     * This function returns a boolean indicating whether the interrupt handling
     * system has been properly initialized and is ready for use.
     *
     * @return bool True if the interrupt system is initialized, false otherwise.
     */
    bool is_initialized(void) {
        return initialized;
    }

    /**
     * @brief Retrieves the address of the Windows NMI handler.
     *
     * This function returns the address of the NMI handler used by the Windows operating system.
     *
     * @return void* The address of the Windows NMI handler.
     */
    void* get_windows_nmi_handler(void) {
        return (void*)g_windows_nmi_handler;
    }
};
