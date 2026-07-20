#pragma once
#include "../project_includes.hpp"

/**
 * @brief Enumeration for exception vectors.
 *
 * This enumeration defines various exception vectors used in the interrupt handling system.
 */
typedef enum {
    /**
     * @brief Nonmaskable Interrupt (NMI).
     *
     * The NMI is a hardware-generated interrupt, triggered by asserting the processor's NMI pin
     * or through an NMI request set by the I/O APIC to the local APIC.
     * Error Code: No.
     */
    nmi = 0x00000002, /**< NMI interrupt vector */
} exception_vector;

/**
 * @brief Structure for the segment descriptor register in 64-bit mode.
 *
 * This structure is used to hold the limit and base address of a segment descriptor.
 */
#pragma pack(push, 1)
typedef struct {
    uint16_t limit; /**< Limit of the segment */
    uint64_t base_address; /**< Base address of the segment */
} segment_descriptor_register_64;
#pragma pack(pop)

/**
 * @brief Structure for a trap frame.
 *
 * This structure represents the state of registers during a context switch or interrupt.
 * It is used to store the state of the processor when an interrupt or exception occurs.
 */
#pragma pack(push, 1)
struct trap_frame_t {
    uint64_t r15; /**< Register r15 */
    uint64_t r14; /**< Register r14 */
    uint64_t r13; /**< Register r13 */
    uint64_t r12; /**< Register r12 */
    uint64_t r11; /**< Register r11 */
    uint64_t r10; /**< Register r10 */
    uint64_t r9; /**< Register r9 */
    uint64_t r8; /**< Register r8 */
    uint64_t rbp; /**< Register rbp */
    uint64_t rdi; /**< Register rdi */
    uint64_t rsi; /**< Register rsi */
    uint64_t rdx; /**< Register rdx */
    uint64_t rcx; /**< Register rcx */
    uint64_t rbx; /**< Register rbx */
    uint64_t rax; /**< Register rax */

    uint64_t rip; /**< Instruction pointer at the time of the interrupt */
    uint64_t cs_selector; /**< Code segment selector */
    uint64_t rflags; /**< CPU flags at the time of the interrupt */
    uint64_t rsp; /**< Stack pointer at the time of the interrupt */
    uint64_t ss_selector; /**< Stack segment selector */
};
#pragma pack(pop)

/**
 * @brief Structure for a segment descriptor for interrupt gates in 64-bit mode.
 *
 * This structure defines an interrupt gate, which describes how interrupts will be handled
 * by the processor, including the segment selector and offset to the interrupt handler.
 */
typedef struct {
    uint16_t offset_low; /**< Lower 16 bits of the interrupt handler's address */
    uint16_t segment_selector; /**< Selector for the code segment */
    union {
        struct {
            uint32_t interrupt_stack_table : 3; /**< Interrupt stack table index */
            uint32_t must_be_zero_0 : 5; /**< Reserved, must be 0 */
            uint32_t type : 4; /**< Type of descriptor (interrupt gate) */
            uint32_t must_be_zero_1 : 1; /**< Reserved, must be 0 */
            uint32_t descriptor_privilege_level : 2; /**< Descriptor privilege level (0-3) */
            uint32_t present : 1; /**< 1 if the interrupt gate is present */
            uint32_t offset_middle : 16; /**< Middle 16 bits of the interrupt handler's address */
        };

        uint32_t flags; /**< Combined 32-bit flags for the interrupt gate */
    };
    uint32_t offset_high; /**< Higher 32 bits of the interrupt handler's address */
    uint32_t reserved; /**< Reserved for future use */
} segment_descriptor_interrupt_gate_64;

/**
 * @brief Union for the RFLAGS register.
 *
 * This union defines the structure of the RFLAGS register, used to represent the CPU flags.
 */
typedef union {
    struct {
        uint64_t carry_flag : 1; /**< Carry flag */
        uint64_t read_as_1 : 1; /**< Reserved bit, read as 1 */
        uint64_t parity_flag : 1; /**< Parity flag */
        uint64_t reserved1 : 1; /**< Reserved bit */
        uint64_t auxiliary_carry_flag : 1; /**< Auxiliary carry flag */
        uint64_t reserved2 : 1; /**< Reserved bit */
        uint64_t zero_flag : 1; /**< Zero flag */
        uint64_t sign_flag : 1; /**< Sign flag */
        uint64_t trap_flag : 1; /**< Trap flag */
        uint64_t interrupt_enable_flag : 1; /**< Interrupt enable flag */
        uint64_t direction_flag : 1; /**< Direction flag */
        uint64_t overflow_flag : 1; /**< Overflow flag */
        uint64_t io_privilege_level : 2; /**< I/O privilege level (0-3) */
        uint64_t nested_task_flag : 1; /**< Nested task flag */
        uint64_t reserved3 : 1; /**< Reserved bit */
        uint64_t resume_flag : 1; /**< Resume flag */
        uint64_t virtual_8086_mode_flag : 1; /**< Virtual 8086 mode flag */
        uint64_t alignment_check_flag : 1; /**< Alignment check flag */
        uint64_t virtual_interrupt_flag : 1; /**< Virtual interrupt flag */
        uint64_t virtual_interrupt_pending_flag : 1; /**< Virtual interrupt pending flag */
        uint64_t identification_flag : 1; /**< Identification flag */
        uint64_t reserved4 : 42; /**< Reserved bits */
    };

    uint64_t flags; /**< Combined 64-bit flags for the RFLAGS register */
} rflags;

/**
 * @brief The IA32_STAR MSR address.
 *
 * This MSR is used to hold the system's return values for system call and return instructions.
 */
#define IA32_STAR 0xC0000081 /**< IA32_STAR MSR address */
