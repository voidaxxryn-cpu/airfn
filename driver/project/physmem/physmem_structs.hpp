#pragma once
#include "../project_includes.hpp"

/**
 * @brief Structure to represent the CPU's split registers from CPUID instruction.
 */
typedef struct {
    uint32_t eax; /**< EAX register value */
    uint32_t ebx; /**< EBX register value */
    uint32_t ecx; /**< ECX register value */
    uint32_t edx; /**< EDX register value */
} cpuidsplit_t;

/**
 * @brief Structure to represent CPUID information for EAX=01h, which contains details about the processor.
 */
typedef struct {
    /**
     * @brief CPUID Version Information (encoded in flags).
     *
     * This union holds the version information returned by the CPUID instruction
     * for EAX=01h. It includes details such as the processor stepping, model,
     * family, and other processor-specific flags.
     */
    union {
        struct {
            uint32_t stepping_id : 4; /**< Processor stepping identifier */
            uint32_t model : 4; /**< Processor model */
            uint32_t family_id : 4; /**< Processor family identifier */
            uint32_t processor_type : 2; /**< Processor type (e.g., original OEM processor) */
            uint32_t reserved1 : 2; /**< Reserved bits */
            uint32_t extended_model_id : 4; /**< Extended model ID */
            uint32_t extended_family_id : 8; /**< Extended family ID */
            uint32_t reserved2 : 4; /**< Reserved bits */
        };

        uint32_t flags; /**< CPUID version information as a raw 32-bit value */
    } cpuid_version_information;

    /**
     * @brief CPUID Additional Information (encoded in flags).
     *
     * This union provides additional information returned by the CPUID instruction,
     * such as the brand index, CLFLUSH line size, maximum addressable IDs, and the
     * initial APIC ID.
     */
    union {
        struct {
            uint32_t brand_index : 8; /**< Brand index of the CPU */
            uint32_t clflush_line_size : 8; /**< CLFLUSH line size */
            uint32_t max_addressable_ids : 8; /**< Maximum addressable IDs supported */
            uint32_t initial_apic_id : 8; /**< Initial APIC ID for the CPU */
        };

        uint32_t flags; /**< CPUID additional information as a raw 32-bit value */
    } cpuid_additional_information;

    /**
     * @brief CPUID Feature Information (encoded in ECX).
     *
     * This union contains a set of flags representing various features supported
     * by the processor. These features include SIMD extensions, debugging capabilities,
     * virtual machine support, and others.
     */
    union {
        struct {
            uint32_t streaming_simd_extensions_3 : 1; /**< SSE3 instructions support */
            uint32_t pclmulqdq_instruction : 1; /**< PCLMULQDQ instruction support */
            uint32_t ds_area_64bit_layout : 1; /**< 64-bit data segment area support */
            uint32_t monitor_mwait_instruction : 1; /**< MONITOR/MWAIT instruction support */
            uint32_t cpl_qualified_debug_store : 1; /**< CPL-qualified debug store support */
            uint32_t virtual_machine_extensions : 1; /**< Virtual Machine Extensions support */
            uint32_t safer_mode_extensions : 1; /**< Safer mode extensions support */
            uint32_t enhanced_intel_speedstep_technology : 1; /**< Enhanced SpeedStep technology support */
            uint32_t thermal_monitor_2 : 1; /**< Thermal monitor 2 support */
            uint32_t supplemental_streaming_simd_extensions_3 : 1; /**< Supplemental SSE3 instructions support */
            uint32_t l1_context_id : 1; /**< L1 cache context ID support */
            uint32_t silicon_debug : 1; /**< Silicon debug support */
            uint32_t fma_extensions : 1; /**< Fused Multiply-Add extensions support */
            uint32_t cmpxchg16b_instruction : 1; /**< CMPXCHG16B instruction support */
            uint32_t xtpr_update_control : 1; /**< XTPR update control support */
            uint32_t perfmon_and_debug_capability : 1; /**< Performance monitoring and debug support */
            uint32_t reserved1 : 1; /**< Reserved */
            uint32_t process_context_identifiers : 1; /**< Support for Process Context Identifiers (PCIDs) */
            uint32_t direct_cache_access : 1; /**< Direct cache access support */
            uint32_t sse41_support : 1; /**< SSE4.1 instructions support */
            uint32_t sse42_support : 1; /**< SSE4.2 instructions support */
            uint32_t x2apic_support : 1; /**< x2APIC support */
            uint32_t movbe_instruction : 1; /**< MOVBE instruction support */
            uint32_t popcnt_instruction : 1; /**< POPCNT instruction support */
            uint32_t tsc_deadline : 1; /**< TSC deadline timer support */
            uint32_t aesni_instruction_extensions : 1; /**< AES-NI instruction extensions support */
            uint32_t xsave_xrstor_instruction : 1; /**< XSAVE/XRSTOR instructions support */
            uint32_t osx_save : 1; /**< OS XSAVE support */
            uint32_t avx_support : 1; /**< AVX instructions support */
            uint32_t half_precision_conversion_instructions : 1; /**< Half-precision conversion instructions support */
            uint32_t rdrand_instruction : 1; /**< RDRAND instruction support */
            uint32_t reserved2 : 1; /**< Reserved */
        };

        uint32_t flags; /**< CPUID feature information ECX as a raw 32-bit value */
    } cpuid_feature_information_ecx;

    /**
     * @brief CPUID Feature Information (encoded in EDX).
     *
     * This union contains flags representing various processor features, including
     * MMX, SSE, and debugging instructions, as well as support for virtual machine
     * technology and hyper-threading.
     */
    union {
        struct {
            uint32_t floating_point_unit_on_chip : 1; /**< FPU on chip */
            uint32_t virtual_8086_mode_enhancements : 1; /**< Virtual 8086 mode enhancements */
            uint32_t debugging_extensions : 1; /**< Debugging extensions */
            uint32_t page_size_extension : 1; /**< Page size extension */
            uint32_t timestamp_counter : 1; /**< Timestamp counter */
            uint32_t rdmsr_wrmsr_instructions : 1; /**< RDMSR/WRMSR instructions support */
            uint32_t physical_address_extension : 1; /**< Physical addresses greater than 32 bits are supported, 2MB pages supported instead of 5MB pages if set */
            uint32_t machine_check_exception : 1; /**< Machine check exception support */
            uint32_t cmpxchg8b : 1; /**< CMPXCHG8B instruction support */
            uint32_t apic_on_chip : 1; /**< APIC on chip */
            uint32_t reserved1 : 1; /**< Reserved */
            uint32_t sysenter_sysexit_instructions : 1; /**< SYSENTER/SYSEXIT instructions support */
            uint32_t memory_type_range_registers : 1; /**< Memory type range registers support */
            uint32_t page_global_bit : 1; /**< Global pages support - If set global pages are supported */
            uint32_t machine_check_architecture : 1; /**< Machine check architecture support */
            uint32_t conditional_move_instructions : 1; /**< Conditional move instructions support */
            uint32_t page_attribute_table : 1; /**< Page attribute table support */
            uint32_t page_size_extension_36bit : 1; /**< 36-bit page size extension */
            uint32_t processor_serial_number : 1; /**< Processor serial number support */
            uint32_t clflush : 1; /**< CLFLUSH instruction support */
            uint32_t reserved2 : 1; /**< Reserved */
            uint32_t debug_store : 1; /**< Debug store support */
            uint32_t thermal_control_msrs_for_acpi : 1; /**< Thermal control MSRs for ACPI support */
            uint32_t mmx_support : 1; /**< MMX support */
            uint32_t fxsave_fxrstor_instructions : 1; /**< FXSAVE/FXRSTOR instructions support */
            uint32_t sse_support : 1; /**< SSE support */
            uint32_t sse2_support : 1; /**< SSE2 support */
            uint32_t self_snoop : 1; /**< Self snoop support */
            uint32_t hyper_threading_technology : 1; /**< Hyper-threading technology support */
            uint32_t thermal_monitor : 1; /**< Thermal monitor support */
            uint32_t reserved3 : 1; /**< Reserved */
            uint32_t pending_break_enable : 1; /**< Pending break enable */
        };

        uint32_t flags; /**< CPUID feature information EDX as a raw 32-bit value */
    } cpuid_feature_information_edx;

} cpuid_eax_01;

/**
 * @brief CR3 Control Register structure, used to store the base address of the page directory.
 *
 * The CR3 register is part of the x86/x86_64 architecture and is used in virtual memory management.
 * It holds the physical address of the page directory for page-level address translation, along with
 * control bits for caching and write-through policies.
 */
typedef union {
    /**
     * @brief Individual bit fields for the CR3 register.
     *
     * The CR3 register contains the base address of the page directory and control bits
     * for the page-level write-through, cache disable, and other related settings.
     */
    struct {
        uint64_t reserved1 : 3; /**< Reserved bits (not used) */
        uint64_t page_level_write_through : 1; /**< Page-level write-through flag (if set, enables write-through caching for the page directory) */
        uint64_t page_level_cache_disable : 1; /**< Page-level cache disable flag (if set, disables caching for the page directory) */
        uint64_t reserved2 : 7; /**< Reserved bits (not used) */
        uint64_t address_of_page_directory : 36; /**< Base address of the page directory (physical address) */
        uint64_t reserved3 : 16; /**< Reserved bits (not used) */
    };

    uint64_t flags; /**< CR3 register value as a raw 64-bit value */
} cr3;

/**
 * @brief CR4 Control Register structure, used for controlling various processor features in x86/x86_64 architectures.
 *
 * The CR4 register is a 64-bit control register that controls various processor-level features, such as virtual mode extensions,
 * debugging, page size extensions, and security-related features. It is important for controlling how the processor interacts
 * with the operating system and memory management.
 */
typedef union {
    /**
     * @brief Individual bit fields for the CR4 register.
     *
     * The CR4 register contains control bits for enabling or disabling several processor features.
     * These bits affect how the processor operates with respect to virtual memory, exception handling, and security features.
     */
    struct {
        uint64_t virtual_mode_extensions : 1; /**< Virtual mode extensions (Enables virtual mode support) */
        uint64_t protected_mode_virtual_interrupts : 1; /**< Protected mode virtual interrupts (Enables virtual interrupts in protected mode) */
        uint64_t timestamp_disable : 1; /**< Disable timestamp counter (Disables the time-stamp counter) */
        uint64_t debugging_extensions : 1; /**< Debugging extensions (Enables debugging support in the processor) */
        uint64_t page_size_extensions : 1; /**< Page size extensions (Enables 4MB pages support in paging) */
        uint64_t physical_address_extension : 1; /**< Physical address extension (Enables 36-bit physical addressing) */
        uint64_t machine_check_enable : 1; /**< Machine check enable (Enables machine check exceptions for hardware errors) */
        uint64_t page_global_enable : 1; /**< Page global enable (Enables global page support in paging) */
        uint64_t performance_monitoring_counter_enable : 1; /**< Performance monitoring counter enable (Enables performance counters) */
        uint64_t os_fxsave_fxrstor_support : 1; /**< OS support for FXSAVE/FXRSTOR (Enables the OS to use FXSAVE/FXRSTOR instructions) */
        uint64_t os_xmm_exception_support : 1; /**< OS support for XMM exception (Enables OS support for SIMD exceptions) */
        uint64_t usermode_instruction_prevention : 1; /**< User-mode instruction prevention (Prevents certain instructions in user mode) */
        uint64_t linear_addresses_57_bit : 1; /**< Linear addresses 57-bit (Enables 57-bit virtual addressing) */
        uint64_t vmx_enable : 1; /**< VMX enable (Enables Intel VT-x virtualization support) */
        uint64_t smx_enable : 1; /**< SMX enable (Enables Intel TXT support for secure execution environments) */
        uint64_t reserved1 : 1; /**< Reserved bit, unused by the processor */
        uint64_t fsgsbase_enable : 1; /**< FSGSBASE enable (Enables access to the FS and GS base registers) */
        uint64_t pcid_enable : 1; /**< PCID enable (Enables support for Process Context Identifiers) */
        uint64_t os_xsave : 1; /**< OS xsave enable (Enables OS support for XSAVE instruction) */
        uint64_t key_locker_enable : 1; /**< Key locker enable (Enables protection against certain types of attacks) */
        uint64_t smep_enable : 1; /**< SMEP enable (Enables Supervisor Mode Execution Protection) */
        uint64_t smap_enable : 1; /**< SMAP enable (Enables Supervisor Mode Access Prevention) */
        uint64_t protection_key_enable : 1; /**< Protection Key enable (Enables the use of protection keys) */
        uint64_t control_flow_enforcement_enable : 1; /**< Control flow enforcement enable (Protects against control flow hijacking) */
        uint64_t protection_key_for_supervisor_mode_enable : 1; /**< Protection Key for supervisor mode enable (Allows protection keys in supervisor mode) */
        uint64_t reserved2 : 39; /**< Reserved bits, unused by the processor */
    };

    uint64_t flags; /**< CR4 register value as a raw 64-bit value */
} cr4;

/**
 * @brief PML4E (Page Map Level 4 Entry) structure for 64-bit paging in x86_64 architecture.
 *
 * The PML4E is used in the 4-level paging model (x86_64) to map virtual addresses to physical addresses.
 * This structure represents a single entry in the PML4 table, where each entry can map a 512 GB range of virtual addresses.
 * The fields control various attributes of the page and its permissions, including access rights, caching policies, and execute-disable features.
 */
typedef union {
    /**
     * @brief Individual bit fields for the PML4E entry.
     *
     * The PML4E entry has several flags that define the permissions, attributes, and address mappings.
     * These fields are used for memory management and controlling access to specific pages.
     */
    struct {
        uint64_t present : 1; /**< Present (Indicates if the page is in memory) */
        uint64_t write : 1; /**< Write (Indicates if the page is writable) */
        uint64_t supervisor : 1; /**< Supervisor (Indicates if the page can be accessed by user-mode or only supervisor-mode) */
        uint64_t page_level_write_through : 1; /**< Page-level write-through (Defines the write-through caching policy for the page) */
        uint64_t page_level_cache_disable : 1; /**< Page-level cache disable (Disables caching for this page) */
        uint64_t accessed : 1; /**< Accessed (Indicates if the page has been accessed recently) */
        uint64_t reserved1 : 1; /**< Reserved bit (Reserved for future use, must be set to 0) */
        uint64_t must_be_zero : 1; /**< Must be zero (Must always be set to 0 by the processor) */
        uint64_t ignored_1 : 4; /**< Ignored bits (These bits are ignored by the processor and can be used for implementation-specific purposes) */
        uint64_t page_frame_number : 36; /**< Page frame number (Physical address of the page) */
        uint64_t reserved2 : 4; /**< Reserved bit (Reserved for future use) */
        uint64_t ignored_2 : 11; /**< Ignored bits (These bits are ignored by the processor and can be used for implementation-specific purposes) */
        uint64_t execute_disable : 1; /**< Execute disable (Prevents execution on this page if set) */
    };

    uint64_t flags; /**< Raw 64-bit value of the PML4E entry, combining all the flags into a single value */
} pml4e_64;

/**
 * @brief PDPTE (Page Directory Pointer Table Entry) for 1 GB page size in 64-bit paging.
 *
 * This structure represents an entry in the Page Directory Pointer Table (PDPTE) for a 1 GB page size in the x86_64 architecture.
 * Each PDPTE maps a 1 GB region of virtual memory to a physical address. This entry controls various attributes of the page, including
 * access permissions, caching policies, and execution restrictions.
 */
typedef union {
    /**
     * @brief Individual bit fields for the PDPTE entry (1 GB page).
     *
     * The PDPTE entry has several flags that define the permissions, attributes, and address mappings for 1 GB pages.
     * These fields help manage memory access and performance, and also provide additional control features such as execute-disable
     * and global page settings.
     */
    struct {
        uint64_t present : 1; /**< Present (Indicates if the page is in memory) */
        uint64_t write : 1; /**< Write (Indicates if the page is writable) */
        uint64_t supervisor : 1; /**< Supervisor (Indicates if the page is restricted to supervisor-mode or accessible to user-mode) */
        uint64_t page_level_write_through : 1; /**< Page-level write-through (Indicates whether write-through caching policy is used) */
        uint64_t page_level_cache_disable : 1; /**< Page-level cache disable (Disables caching for this page) */
        uint64_t accessed : 1; /**< Accessed (Indicates if the page has been accessed recently) */
        uint64_t dirty : 1; /**< Dirty (Indicates if the page has been written to since the last time it was cleared) */
        uint64_t large_page : 1; /**< Large page (Indicates that this entry maps a large page, specifically 1 GB in size) */
        uint64_t global : 1; /**< Global (If set, the page is global and not subject to certain page replacement policies) */
        uint64_t ignored_1 : 3; /**< Ignored bits (These bits are ignored by the processor and can be used for implementation-specific purposes) */
        uint64_t pat : 1; /**< PAT (Page Attribute Table, determines the caching policy for the page) */
        uint64_t reserved1 : 17; /**< Reserved (These bits are reserved for future use and must be set to 0) */
        uint64_t page_frame_number : 18; /**< Page frame number (Physical address of the page for the 1 GB region) */
        uint64_t reserved2 : 4; /**< Reserved (These bits are reserved for future use) */
        uint64_t ignored_2 : 7; /**< Ignored bits (These bits are ignored by the processor and can be used for implementation-specific purposes) */
        uint64_t protection_key : 4; /**< Protection key (Used for managing memory access restrictions, e.g., for memory isolation) */
        uint64_t execute_disable : 1; /**< Execute disable (If set, prevents the execution of code from this page) */
    };

    uint64_t flags; /**< Raw 64-bit value of the PDPTE entry, combining all the flags into a single value */
} pdpte_1gb_64;

/**
 * @brief PDPTE (Page Directory Pointer Table Entry) for standard 64-bit page size.
 *
 * This structure represents an entry in the Page Directory Pointer Table (PDPTE) for a standard 4 KB page size in the x86_64 architecture.
 * Each PDPTE maps a region of virtual memory to a physical address. This entry controls various attributes of the page, including
 * access permissions, caching policies, and execution restrictions.
 */
typedef union {
    /**
     * @brief Individual bit fields for the PDPTE entry (standard 64-bit page).
     *
     * The PDPTE entry has several flags that define the permissions, attributes, and address mappings for standard pages.
     * These fields help manage memory access, page replacement, caching, and other memory-related operations.
     */
    struct {
        uint64_t present : 1; /**< Present (Indicates if the page is in memory) */
        uint64_t write : 1; /**< Write (Indicates if the page is writable) */
        uint64_t supervisor : 1; /**< Supervisor (Indicates if the page is restricted to supervisor-mode or accessible to user-mode) */
        uint64_t page_level_write_through : 1; /**< Page-level write-through (Indicates whether write-through caching policy is used) */
        uint64_t page_level_cache_disable : 1; /**< Page-level cache disable (Disables caching for this page) */
        uint64_t accessed : 1; /**< Accessed (Indicates if the page has been accessed recently) */
        uint64_t reserved1 : 1; /**< Reserved (This bit is reserved for future use and must be set to 0) */
        uint64_t large_page : 1; /**< Large page (Indicates that this entry maps a large page) */
        uint64_t ignored_1 : 4; /**< Ignored bits (These bits are ignored by the processor and can be used for implementation-specific purposes) */
        uint64_t page_frame_number : 36; /**< Page frame number (Physical address of the page for the region) */
        uint64_t reserved2 : 4; /**< Reserved (These bits are reserved for future use) */
        uint64_t ignored_2 : 11; /**< Ignored bits (These bits are ignored by the processor and can be used for implementation-specific purposes) */
        uint64_t execute_disable : 1; /**< Execute disable (If set, prevents the execution of code from this page) */
    };

    uint64_t flags; /**< Raw 64-bit value of the PDPTE entry, combining all the flags into a single value */
} pdpte_64;

/**
 * @brief PDE (Page Directory Entry) for 2 MB page size in 64-bit paging.
 *
 * This structure represents an entry in the Page Directory Entry (PDE) for a 2 MB page size in the x86_64 architecture.
 * Each PDE maps a larger region of virtual memory to a physical address. The entry controls various attributes of the page,
 * including access permissions, caching policies, and execution restrictions for 2 MB pages.
 */
typedef union {
    /**
     * @brief Individual bit fields for the 2 MB PDE entry.
     *
     * The 2 MB PDE entry has several flags that define the permissions, attributes, and address mappings for large pages.
     * These flags help manage memory access, page replacement, caching, and other memory-related operations specific to 2 MB pages.
     */
    struct {
        uint64_t present : 1; /**< Present (Indicates if the page is in memory) */
        uint64_t write : 1; /**< Write (Indicates if the page is writable) */
        uint64_t supervisor : 1; /**< Supervisor (Indicates if the page is restricted to supervisor-mode or accessible to user-mode) */
        uint64_t page_level_write_through : 1; /**< Page-level write-through (Indicates whether write-through caching policy is used) */
        uint64_t page_level_cache_disable : 1; /**< Page-level cache disable (Disables caching for this page) */
        uint64_t accessed : 1; /**< Accessed (Indicates if the page has been accessed recently) */
        uint64_t dirty : 1; /**< Dirty (Indicates if the page has been written to) */
        uint64_t large_page : 1; /**< Large page (Indicates that this entry maps a large page of 2 MB size) */
        uint64_t global : 1; /**< Global (Indicates if the page is global across all processes) */
        uint64_t ignored_1 : 3; /**< Ignored bits (These bits are ignored by the processor and can be used for implementation-specific purposes) */
        uint64_t pat : 1; /**< PAT (Page Attribute Table, for controlling the caching behavior of the page) */
        uint64_t reserved1 : 8; /**< Reserved (These bits are reserved for future use and must be set to 0) */
        uint64_t page_frame_number : 27; /**< Page frame number (Physical address of the 2 MB page) */
        uint64_t reserved2 : 4; /**< Reserved (These bits are reserved for future use and must be set to 0) */
        uint64_t ignored_2 : 7; /**< Ignored bits (These bits are ignored by the processor and can be used for implementation-specific purposes) */
        uint64_t protection_key : 4; /**< Protection key (Allows control over memory protection, if enabled) */
        uint64_t execute_disable : 1; /**< Execute disable (If set, prevents the execution of code from this page) */
    };

    uint64_t flags; /**< Raw 64-bit value of the PDE entry, combining all the flags into a single value */
} pde_2mb_64;

/**
 * @brief PDE (Page Directory Entry) for 64-bit paging.
 *
 * This structure represents an entry in the Page Directory Entry (PDE) for a 64-bit page in the x86_64 architecture.
 * Each PDE maps a region of virtual memory to a physical address. The entry controls various attributes of the page,
 * including access permissions, caching policies, and execution restrictions for the page.
 */
typedef union {
    /**
     * @brief Individual bit fields for the 64-bit PDE entry.
     *
     * The 64-bit PDE entry has several flags that define the permissions, attributes, and address mappings for 64-bit pages.
     * These flags help manage memory access, page replacement, caching, and other memory-related operations specific to 64-bit pages.
     */
    struct {
        uint64_t present : 1; /**< Present (Indicates if the page is in memory) */
        uint64_t write : 1; /**< Write (Indicates if the page is writable) */
        uint64_t supervisor : 1; /**< Supervisor (Indicates if the page is restricted to supervisor-mode or accessible to user-mode) */
        uint64_t page_level_write_through : 1; /**< Page-level write-through (Indicates whether write-through caching policy is used) */
        uint64_t page_level_cache_disable : 1; /**< Page-level cache disable (Disables caching for this page) */
        uint64_t accessed : 1; /**< Accessed (Indicates if the page has been accessed recently) */
        uint64_t reserved1 : 1; /**< Reserved (These bits are reserved for future use and must be set to 0) */
        uint64_t large_page : 1; /**< Large page (Indicates that this entry maps a large page) */
        uint64_t ignored_1 : 4; /**< Ignored bits (These bits are ignored by the processor and can be used for implementation-specific purposes) */
        uint64_t page_frame_number : 36; /**< Page frame number (Physical address of the page) */
        uint64_t reserved2 : 4; /**< Reserved (These bits are reserved for future use and must be set to 0) */
        uint64_t ignored_2 : 11; /**< Ignored bits (These bits are ignored by the processor and can be used for implementation-specific purposes) */
        uint64_t execute_disable : 1; /**< Execute disable (If set, prevents the execution of code from this page) */
    };

    uint64_t flags; /**< Raw 64-bit value of the PDE entry, combining all the flags into a single value */
} pde_64;


/**
 * @brief PTE (Page Table Entry) for 64-bit paging.
 *
 * This structure represents an entry in the Page Table Entry (PTE) for a 64-bit page in the x86_64 architecture.
 * Each PTE maps a virtual memory address to a physical address for a 4KB page. It also controls various attributes
 * of the page, including access permissions, caching policies, and execution restrictions.
 */
typedef union {
    /**
     * @brief Individual bit fields for the 64-bit PTE entry.
     *
     * The 64-bit PTE entry has several flags that define the permissions, attributes, and address mappings for 64-bit pages.
     * These flags help manage memory access, page replacement, caching, and other memory-related operations specific to 64-bit pages.
     */
    struct {
        uint64_t present : 1; /**< Present (Indicates if the page is in memory) */
        uint64_t write : 1; /**< Write (Indicates if the page is writable) */
        uint64_t supervisor : 1; /**< Supervisor (Indicates if the page is restricted to supervisor-mode or accessible to user-mode) */
        uint64_t page_level_write_through : 1; /**< Page-level write-through (Indicates whether write-through caching policy is used) */
        uint64_t page_level_cache_disable : 1; /**< Page-level cache disable (Disables caching for this page) */
        uint64_t accessed : 1; /**< Accessed (Indicates if the page has been accessed recently) */
        uint64_t dirty : 1; /**< Dirty (Indicates if the page has been modified) */
        uint64_t pat : 1; /**< PAT (Page Attribute Table: Determines cacheability) */
        uint64_t global : 1; /**< Global (Indicates if the page is a global page) */
        uint64_t ignored_1 : 3; /**< Ignored bits (These bits are ignored by the processor and can be used for implementation-specific purposes) */
        uint64_t page_frame_number : 36; /**< Page frame number (Physical address of the page) */
        uint64_t reserved1 : 4; /**< Reserved (These bits are reserved for future use and must be set to 0) */
        uint64_t ignored_2 : 7; /**< Ignored bits (These bits are ignored by the processor and can be used for implementation-specific purposes) */
        uint64_t protection_key : 4; /**< Protection key (A key for protection against access violations) */
        uint64_t execute_disable : 1; /**< Execute disable (If set, prevents the execution of code from this page) */
    };

    uint64_t flags; /**< Raw 64-bit value of the PTE entry, combining all the flags into a single value */
} pte_64;

/**
 * @brief Page Table Entry (PTE) for a 64-bit Page Table.
 *
 * This structure represents an entry in the Page Table Entry (PTE) for a 64-bit page in x86_64 architecture.
 * Each PTE maps a virtual address to a physical address and holds several control flags for managing memory
 * access permissions, caching policies, and protection attributes for a specific 4KB page.
 */
typedef union {
    /**
     * @brief Individual bit fields for the 64-bit PTE entry.
     *
     * The 64-bit PTE entry contains flags that manage various attributes of the page, including access permissions,
     * cacheability, and page management. These flags are used by the processor to control the page-level memory management.
     */
    struct {
        uint64_t present : 1; /**< Present (Indicates if the page is in memory) */
        uint64_t write : 1; /**< Write (Indicates if the page is writable) */
        uint64_t supervisor : 1; /**< Supervisor (Indicates if the page is accessible only in supervisor mode) */
        uint64_t page_level_write_through : 1; /**< Page-level write-through (Indicates if write-through caching is used) */
        uint64_t page_level_cache_disable : 1; /**< Page-level cache disable (Indicates if caching is disabled for this page) */
        uint64_t accessed : 1; /**< Accessed (Indicates if the page has been accessed) */
        uint64_t dirty : 1; /**< Dirty (Indicates if the page has been written to) */
        uint64_t large_page : 1; /**< Large page (Indicates if the page is a large page) */
        uint64_t global : 1; /**< Global (Indicates if the page is a global page) */
        uint64_t ignored_1 : 2; /**< Ignored bits (These bits are reserved and must be set to 0) */
        uint64_t restart : 1; /**< Restart (Indicates a restart of the page table entry lookup) */
        uint64_t page_frame_number : 36; /**< Page frame number (Physical address of the page) */
        uint64_t reserved1 : 4; /**< Reserved (These bits are reserved for future use and must be set to 0) */
        uint64_t ignored_2 : 7; /**< Ignored bits (These bits are reserved and must be set to 0) */
        uint64_t protection_key : 4; /**< Protection key (A key for protecting access to the page) */
        uint64_t execute_disable : 1; /**< Execute disable (If set, prevents execution from this page) */
    };

    uint64_t flags; /**< Raw 64-bit value representing the PTE entry */
} pt_entry_64;


/**
 * @brief Virtual Address Structure for 64-bit Address Translation.
 *
 * This structure represents a virtual address in a 64-bit paging system. It contains different levels of address
 * translation indices (PML4e, PDPT, PDE, and PTE) and the offset within the page, depending on the page size (4KB,
 * 2MB, or 1GB). The structure can be used to extract and manipulate various components of a 64-bit virtual address.
 *
 * The union contains three different bitfield structures to represent different page sizes: 1GB, 2MB, and 4KB.
 * The appropriate structure is chosen based on the size of the page being accessed, allowing for flexibility in
 * address translation.
 */
typedef union {

    /**
     * @brief Representation for 1GB Page Address Translation.
     *
     * This structure represents the components of a 64-bit virtual address when the page size is 1GB.
     * It contains the offset, PDPT index, and PML4e index, along with reserved bits.
     */
    struct {
        uint64_t offset_1gb : 30; /**< 30-bit offset within a 1GB page */
        uint64_t pdpte_idx : 9;   /**< 9-bit index into the PDPT (Page Directory Pointer Table) */
        uint64_t pml4e_idx : 9;   /**< 9-bit index into the PML4e (Page Map Level 4) */
        uint64_t reserved : 16;    /**< Reserved bits, must be set to 0 */
    };

    /**
     * @brief Representation for 2MB Page Address Translation.
     *
     * This structure represents the components of a 64-bit virtual address when the page size is 2MB.
     * It contains the offset, PDE index, PDPT index, and PML4e index, along with reserved bits.
     */
    struct {
        uint64_t offset_2mb : 21; /**< 21-bit offset within a 2MB page */
        uint64_t pde_idx : 9;     /**< 9-bit index into the PDE (Page Directory Entry) */
        uint64_t pdpte_idx : 9;   /**< 9-bit index into the PDPT (Page Directory Pointer Table) */
        uint64_t pml4e_idx : 9;   /**< 9-bit index into the PML4e (Page Map Level 4) */
        uint64_t reserved : 16;    /**< Reserved bits, must be set to 0 */
    };

    /**
     * @brief Representation for 4KB Page Address Translation.
     *
     * This structure represents the components of a 64-bit virtual address when the page size is 4KB.
     * It contains the offset, PTE index, PDE index, PDPT index, and PML4e index, along with reserved bits.
     */
    struct {
        uint64_t offset_4kb : 12; /**< 12-bit offset within a 4KB page */
        uint64_t pte_idx : 9;     /**< 9-bit index into the PTE (Page Table Entry) */
        uint64_t pde_idx : 9;     /**< 9-bit index into the PDE (Page Directory Entry) */
        uint64_t pdpte_idx : 9;   /**< 9-bit index into the PDPT (Page Directory Pointer Table) */
        uint64_t pml4e_idx : 9;   /**< 9-bit index into the PML4e (Page Map Level 4) */
        uint64_t reserved : 16;    /**< Reserved bits, must be set to 0 */
    };

    uint64_t flags; /**< Raw 64-bit value representing the virtual address */
} va_64_t;

/**
 * @brief Slot structure used to represent a page table entry (PTE), page directory (PDE), or page directory pointer (PDPT).
 *
 * This structure holds a pointer to a table (e.g., PDPT, PDE, or PTE) and a flag indicating whether the table is
 * for a large page (e.g., 2MB or 1GB page size).
 */
typedef struct {
    void* table; /**< Pointer to the page table (PDPT, PDE, or PTE) */
    bool large_page; /**< Flag indicating if the table is for a large page (2MB or 1GB) */
} slot_t;


/**
 * @brief A structure representing a remapped virtual address entry.
 *
 * This structure is used to represent a remapped virtual address and the associated page tables (PDPT, PDE, PTE)
 * that support the remapping. It contains information about the remapped virtual address and the various page tables
 * used in the remapping process. The `used` field is a flag indicating whether the remapped entry is currently in use.
 */
typedef struct {
    va_64_t remapped_va; /**< Remapped virtual address in 64-bit format */

    slot_t pdpt_table; /**< Slot for the Page Directory Pointer Table (PDPT) */
    slot_t pd_table;   /**< Slot for the Page Directory Table (PDT) */
    void* pt_table;    /**< Pointer to the Page Table (PT) */

    bool used; /**< Flag indicating whether this remapped entry is currently in use */
} remapped_entry_t;


/**
 * @brief Enum representing the validity state of a page table entry during the remapping process.
 *
 * This enum is used to track the validity state of the different levels of the page table during the remapping process.
 * It helps identify which page table is valid and already remapped.
 */
typedef enum {
    pdpt_table_valid, /**< The PML4 at the correct index already points to a valid remapped PDPT table */
    pde_table_valid,  /**< The PDPT at the correct index already points to a valid remapped PDE table */
    pte_table_valid,  /**< The PDE at the correct index already points to a valid remapped PTE table */
    non_valid,        /**< The PML4 indexes didn't match, indicating an invalid remapped entry */
} usable_until_t;

/**
 * @brief The number of entries in each page table (PML4, PDPT, PDE).
 *
 * Defines the size of the page tables in the paging structure. Each page table (PML4, PDPT, PDE) will have
 * this number of entries, which corresponds to the 512 entries used in x86-64 paging.
 */
#define PAGE_TABLE_ENTRY_COUNT 512


 /**
  * @brief Structure representing the entire page table hierarchy.
  *
  * This structure holds the page tables required for the virtual memory management system. It includes
  * the PML4 table, the PDPT (Page Directory Pointer Table), and the PDE (Page Directory Entry) table.
  * These page tables are aligned to the required 4KB boundaries using the `alignas` keyword, ensuring proper memory
  * alignment for efficient paging and address translation.
  */
typedef struct {
    alignas(0x1000) pml4e_64 pml4_table[PAGE_TABLE_ENTRY_COUNT]; /**< PML4 table with 512 entries, each representing a 64-bit page map level entry */

    alignas(0x1000) pdpte_64 pdpt_table[PAGE_TABLE_ENTRY_COUNT]; /**< PDPT table with 512 entries, each representing a 64-bit page directory pointer entry */

    alignas(0x1000) pde_2mb_64 pd_2mb_table[PAGE_TABLE_ENTRY_COUNT][PAGE_TABLE_ENTRY_COUNT]; /**< 2MB page table with 512x512 entries, each representing a 2MB page directory entry */
} page_tables_t;

#define REMAPPING_TABLE_COUNT 100 /**< The number of remapping tables */
#define MAX_REMAPPINGS 100 /**< The maximum number of remappings */

/**
 * @brief Structure representing remapping tables for virtual-to-physical memory address translation.
 */
typedef struct {
    /**
     * @brief Union that holds the PDPT (Page Directory Pointer Table) entries.
     *
     * This union allows for different types of page size mappings:
     * - pdpte_64 for standard entries.
     * - pdpte_1gb_64 for 1GB large page entries.
     */
    union {
        pdpte_64* pdpt_table[REMAPPING_TABLE_COUNT]; /**< Array of PDPT entries */
        pdpte_1gb_64* pdpt_1gb_table[REMAPPING_TABLE_COUNT]; /**< Array of 1GB PDPT entries */
    };

    /**
     * @brief Union that holds the PDE (Page Directory Entry) entries.
     *
     * This union allows for different types of page directory entries:
     * - pde_64 for standard entries.
     * - pde_2mb_64 for 2MB large page entries.
     */
    union {
        pde_64* pd_table[REMAPPING_TABLE_COUNT]; /**< Array of PDE entries */
        pde_2mb_64* pd_2mb_table[REMAPPING_TABLE_COUNT]; /**< Array of 2MB PDE entries */
    };

    /**
     * @brief Array of PTE (Page Table Entry) entries.
     */
    pte_64* pt_table[REMAPPING_TABLE_COUNT]; /**< Array of PTE entries */

    /**
     * @brief Array of boolean values indicating whether each PDPT table is occupied.
     */
    bool is_pdpt_table_occupied[REMAPPING_TABLE_COUNT]; /**< Occupied status of PDPT tables */

    /**
     * @brief Array of boolean values indicating whether each PDE table is occupied.
     */
    bool is_pd_table_occupied[REMAPPING_TABLE_COUNT]; /**< Occupied status of PDE tables */

    /**
     * @brief Array of boolean values indicating whether each PTE table is occupied.
     */
    bool is_pt_table_occupied[REMAPPING_TABLE_COUNT]; /**< Occupied status of PTE tables */

    /**
     * @brief List of remapped entries for virtual to physical address mapping.
     */
    remapped_entry_t remapping_list[MAX_REMAPPINGS]; /**< List of remapping entries */
} remapping_tables_t;

/**
 * @brief Structure representing the physical memory management.
 *
 * This structure encapsulates all the necessary data to manage and remap physical memory in a system. It stores the
 * page tables used for virtual-to-physical address translation, the remapping tables for address translation, and the
 * current CR3 values for kernel and constructed paging states.
 *
 * It also tracks whether the physical memory management system has been initialized and includes the base address
 * of the first 512GB of physical memory that has been mapped. This allows for an organized way of managing and
 * modifying physical memory mappings.
 */
typedef struct {
    /**
     * @brief Pointer to the page tables used for CR3.
     *
     * This is a pointer to a `page_tables_t` structure, which contains the page tables (PML4, PDPT, PDE) used for
     * address translation and are included in the CR3 register for virtual memory management.
     */
    page_tables_t* page_tables;

    /**
     * @brief The remapping tables used to remap addresses.
     *
     * The `remapping_tables_t` structure holds the tables used to remap physical addresses. These entries are critical
     * for modifying the system's memory mappings during address translation.
     */
    remapping_tables_t remapping_tables;

    /**
     * @brief The current CR3 value for the kernel.
     *
     * This field stores the kernel's CR3 value, which points to the base of the page tables used by the kernel to
     * manage virtual memory. It is used for handling address space switches and controlling memory access at the
     * kernel level.
     */
    cr3 kernel_cr3;

    /**
     * @brief The constructed CR3 value.
     *
     * This field holds the CR3 value that has been constructed based on the current page tables and remapping information.
     * It represents the physical memory's structure after the necessary mappings have been applied.
     */
    cr3 constructed_cr3;

    /**
     * @brief The base address of the mapped physical memory.
     *
     * This field holds the base address where the first 512GB of physical memory have been mapped. It is used for
     * handling large memory ranges in the system and enables efficient memory access and management.
     */
    uint64_t mapped_physical_mem_base;

    /**
     * @brief Whether the physical memory system has been initialized.
     *
     * A boolean flag that indicates whether the physical memory management system has been properly initialized.
     * If true, the system is ready for address remapping and paging operations. Otherwise, initialization has not yet
     * occurred, and memory management is not active.
     */
    bool initialized;
} physmem_t;

