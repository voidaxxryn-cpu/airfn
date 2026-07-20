#pragma once
#include <ntddk.h>
#include <intrin.h>
#include "offset_resolver.hpp"

/*
    Dynamic offsets in windows; Resolved at runtime for compatibility with all Windows versions
*/

/**
 * @brief Compile-time constants
 * 
 * These values are fixed across all Windows versions and can be used as compile-time constants.
 */
#define IMAGE_NAME_LENGTH 15              /**< Maximum length for the image name (fixed in Windows) */
#define SYSTEM_PID 4                      /**< The PID of the system process (always 4) */

/**
 * @brief Macros for accessing dynamically resolved kernel structure offsets
 * 
 * These macros provide access to offsets that are resolved at runtime by the offset_resolver module.
 * This ensures compatibility with different Windows versions and builds.
 * 
 * Note: offset_resolver::initialize_offsets() must be called before using these macros.
 */
#define IMAGE_NAME_OFFSET (offset_resolver::g_offsets.image_name)           /**< Offset for the image name */
#define PID_OFFSET (offset_resolver::g_offsets.pid)                         /**< Offset for the process ID */
#define FLINK_OFFSET (offset_resolver::g_offsets.flink)                     /**< Offset for the next entry in a list (Flink) */
#define LIST_ENTRY_OFFSET (offset_resolver::g_offsets.flink)                /**< Offset for the list entry structure */
#define DIRECTORY_TABLE_BASE_OFFSET (offset_resolver::g_offsets.directory_table_base) /**< Offset for the directory table base */
#define PEB_OFFSET (offset_resolver::g_offsets.peb)                         /**< Offset for the Process Environment Block (PEB) */
#define ACTIVE_THREADS (offset_resolver::g_offsets.active_threads)          /**< Offset for active threads count */
#define LDR_DATA_OFFSET (offset_resolver::g_offsets.ldr_data)               /**< Offset for the loader data structure */

 /**
  * @brief Union to represent the options related to process execution.
  *
  * This union is used to control the execution behavior of a process at the kernel level.
  * Flags in this structure control various aspects like execution enable/disable and exception chain validation.
  */
union _KEXECUTE_OPTIONS {
    UCHAR ExecuteDisable : 1;           /**< Disable execution */
    UCHAR ExecuteEnable : 1;            /**< Enable execution */
    UCHAR DisableThunkEmulation : 1;    /**< Disable thunk emulation */
    UCHAR Permanent : 1;                /**< Permanent execution setting */
    UCHAR ExecuteDispatchEnable : 1;    /**< Enable dispatching execution */
    UCHAR ImageDispatchEnable : 1;      /**< Enable image dispatching */
    UCHAR DisableExceptionChainValidation : 1; /**< Disable exception chain validation */
    UCHAR Spare : 1;                    /**< Reserved for future use */
    volatile UCHAR ExecuteOptions;      /**< General execution options */
    UCHAR ExecuteOptionsNV;             /**< Non-volatile execution options */
};

/**
 * @brief Union to represent the stack count for a kernel process.
 *
 * This union tracks the stack count and can store a state indicating whether the stack
 * is being used or not. It helps manage the kernel stack's usage within a process.
 */
union _KSTACK_COUNT {
    LONG Value;                         /**< Stack count value */
    ULONG State : 3;                    /**< Stack state (3-bit state) */
    ULONG StackCount : 29;              /**< Stack count (29-bit count) */
};

/**
 * @brief Structure representing processor affinity for a kernel process.
 *
 * This structure is used to define the set of processors a process can run on.
 * It is part of managing CPU scheduling for kernel processes.
 */
struct _KAFFINITY_EX {
    USHORT Count;                       /**< Number of processors in the affinity set */
    USHORT Size;                        /**< Size of the structure */
    ULONG Reserved;                     /**< Reserved for future use */
    ULONGLONG Bitmap[20];               /**< Processor affinity bitmap */
};

/**
 * @brief Kernel process structure.
 *
 * This structure holds information related to a process in the kernel,
 * including its state, thread list, processor affinity, and more. The offsets
 * for this structure may vary based on the Windows version.
 */
struct _KPROCESS {
    struct _DISPATCHER_HEADER Header;                   /**< Dispatcher header */
    struct _LIST_ENTRY ProfileListHead;                 /**< List of profiles associated with the process */
    ULONGLONG DirectoryTableBase;                       /**< Base of the directory table */
    struct _LIST_ENTRY ThreadListHead;                  /**< List of threads in the process */
    ULONG ProcessLock;                                  /**< Lock for the process */
    ULONG ProcessTimerDelay;                            /**< Timer delay for the process */
    ULONGLONG DeepFreezeStartTime;                      /**< Time when the process was frozen */
    struct _KAFFINITY_EX Affinity;                      /**< Processor affinity information */
    ULONGLONG AffinityPadding[12];                      /**< Padding for alignment */
    struct _LIST_ENTRY ReadyListHead;                   /**< List of ready threads */
    struct _SINGLE_LIST_ENTRY SwapListEntry;            /**< Swap list entry */
    volatile struct _KAFFINITY_EX ActiveProcessors;     /**< Active processors for the process */
    ULONGLONG ActiveProcessorsPadding[12];              /**< Padding for alignment */
    union {
        struct {
            ULONG AutoAlignment : 1;                     /**< Flag for auto-alignment */
            ULONG DisableBoost : 1;                       /**< Flag to disable boost */
            ULONG DisableQuantum : 1;                     /**< Flag to disable quantum */
            ULONG DeepFreeze : 1;                         /**< Flag for deep freeze */
            ULONG TimerVirtualization : 1;                /**< Timer virtualization enabled */
            ULONG CheckStackExtents : 1;                  /**< Flag to check stack extents */
            ULONG CacheIsolationEnabled : 1;              /**< Flag for cache isolation */
            ULONG PpmPolicy : 3;                          /**< Power policy management */
            ULONG VaSpaceDeleted : 1;                     /**< Flag indicating address space deletion */
            ULONG ReservedFlags : 21;                     /**< Reserved flags */
        };
        volatile LONG ProcessFlags;                       /**< Flags related to the process */
    };
    ULONG ActiveGroupsMask;                             /**< Mask of active processor groups */
    CHAR BasePriority;                                  /**< Base priority of the process */
    CHAR QuantumReset;                                  /**< Quantum reset value */
    CHAR Visited;                                       /**< Flag indicating if the process has been visited */
    union _KEXECUTE_OPTIONS Flags;                      /**< Execution flags */
    USHORT ThreadSeed[20];                              /**< Seed for thread scheduling */
    USHORT ThreadSeedPadding[12];                       /**< Padding for alignment */
    USHORT IdealProcessor[20];                          /**< Ideal processor for the thread */
    USHORT IdealProcessorPadding[12];                   /**< Padding for alignment */
    USHORT IdealNode[20];                               /**< Ideal node for the thread */
    USHORT IdealNodePadding[12];                        /**< Padding for alignment */
    USHORT IdealGlobalNode;                             /**< Ideal global node */
    USHORT Spare1;                                      /**< Reserved for future use */
    _KSTACK_COUNT StackCount;                           /**< Stack count information */
    struct _LIST_ENTRY ProcessListEntry;                /**< List entry for the process */
    ULONGLONG CycleTime;                                /**< Cycle time of the process */
    ULONGLONG ContextSwitches;                          /**< Number of context switches for the process */
    struct _KSCHEDULING_GROUP* SchedulingGroup;         /**< Scheduling group for the process */
    ULONG FreezeCount;                                  /**< Freeze count */
    ULONG KernelTime;                                   /**< Kernel time used by the process */
    ULONG UserTime;                                     /**< User time used by the process */
    ULONG ReadyTime;                                    /**< Time when the process became ready */
    ULONGLONG UserDirectoryTableBase;                   /**< Base of the user directory table */
    UCHAR AddressPolicy;                                /**< Address policy */
    UCHAR Spare2[71];                                   /**< Reserved for future use */
    VOID* InstrumentationCallback;                      /**< Callback function for instrumentation */
    union {
        ULONGLONG SecureHandle;                         /**< Secure handle */
        struct {
            ULONGLONG SecureProcess : 1;                /**< Flag for secure process */
            ULONGLONG Unused : 1;                       /**< Unused bit */
        } Flags;
    } SecureState;                                      /**< Secure state of the process */
    ULONGLONG KernelWaitTime;                           /**< Wait time in kernel mode */
    ULONGLONG UserWaitTime;                             /**< Wait time in user mode */
    ULONGLONG EndPadding[8];                            /**< Padding for structure alignment */
};

/**
 * @brief Structure representing a loaded module in the loader.
 *
 * This structure holds information about a loaded DLL or executable, including
 * its memory address, entry point, flags, and various other details.
 */
typedef struct {
    struct _LIST_ENTRY InLoadOrderLinks;              /**< List entry in the load order */
    struct _LIST_ENTRY InMemoryOrderLinks;            /**< List entry in the memory order */
    struct _LIST_ENTRY InInitializationOrderLinks;    /**< List entry in the initialization order */
    VOID* DllBase;                                    /**< Base address of the DLL */
    VOID* EntryPoint;                                 /**< Entry point for the DLL */
    ULONG SizeOfImage;                                /**< Size of the loaded image */
    struct _UNICODE_STRING FullDllName;               /**< Full path name of the DLL */
    struct _UNICODE_STRING BaseDllName;               /**< Base name of the DLL */
    union {
        UCHAR FlagGroup[4];                           /**< Group of flags */
        ULONG Flags;                                  /**< Flags related to the DLL */
        struct {
            ULONG PackagedBinary : 1;                 /**< Flag indicating packaged binary */
            ULONG MarkedForRemoval : 1;                /**< Flag for removal status */
            ULONG ImageDll : 1;                        /**< Flag indicating image DLL */
            ULONG LoadNotificationsSent : 1;           /**< Flag indicating if load notifications were sent */
            ULONG TelemetryEntryProcessed : 1;         /**< Telemetry entry processed flag */
            ULONG ProcessStaticImport : 1;             /**< Static import process flag */
            ULONG InLegacyLists : 1;                   /**< Flag for legacy lists */
            ULONG InIndexes : 1;                       /**< Flag for indexes */
            ULONG ShimDll : 1;                         /**< Shim DLL flag */
            ULONG InExceptionTable : 1;                /**< Flag indicating presence in exception table */
            ULONG ReservedFlags1 : 2;                  /**< Reserved flags */
            ULONG LoadInProgress : 1;                  /**< Flag for load in progress */
            ULONG LoadConfigProcessed : 1;             /**< Flag for processed load configuration */
            ULONG EntryProcessed : 1;                  /**< Flag for entry processed */
            ULONG ProtectDelayLoad : 1;                /**< Flag for protected delay load */
            ULONG ReservedFlags3 : 2;                  /**< Reserved flags */
            ULONG DontCallForThreads : 1;              /**< Flag indicating no thread calls */
            ULONG ProcessAttachCalled : 1;             /**< Flag for process attach call */
            ULONG ProcessAttachFailed : 1;             /**< Flag for failed process attach */
            ULONG CorDeferredValidate : 1;             /**< Flag for deferred validation */
            ULONG CorImage : 1;                        /**< Flag for a COR image */
            ULONG DontRelocate : 1;                    /**< Flag for relocation */
            ULONG CorILOnly : 1;                       /**< Flag for COR IL-only image */
            ULONG ChpeImage : 1;                       /**< Flag for CHPE image */
            ULONG ReservedFlags5 : 2;                  /**< Reserved flags */
            ULONG Redirected : 1;                      /**< Flag for redirected image */
            ULONG ReservedFlags6 : 2;                  /**< Reserved flags */
            ULONG CompatDatabaseProcessed : 1;         /**< Flag for compatibility database processed */
        };
    };
    USHORT ObsoleteLoadCount;                         /**< Obsolete load count */
    USHORT TlsIndex;                                  /**< TLS index */
    struct _LIST_ENTRY HashLinks;                     /**< Hash links for the module */
    ULONG TimeDateStamp;                              /**< Time and date stamp of the module */
    struct _ACTIVATION_CONTEXT* EntryPointActivationContext; /**< Activation context for the entry point */
    VOID* Lock;                                       /**< Lock for the module */
    struct _LDR_DDAG_NODE* DdagNode;                  /**< Node in the loader DAG */
    struct _LIST_ENTRY NodeModuleLink;                /**< Module link in the loader */
    struct _LDRP_LOAD_CONTEXT* LoadContext;           /**< Context for the module load */
    VOID* ParentDllBase;                              /**< Parent DLL base */
    VOID* SwitchBackContext;                          /**< Context for switchback */
    struct _RTL_BALANCED_NODE BaseAddressIndexNode;   /**< Base address index node */
    struct _RTL_BALANCED_NODE MappingInfoIndexNode;   /**< Mapping information index node */
    ULONGLONG OriginalBase;                           /**< Original base address */
    union _LARGE_INTEGER LoadTime;                    /**< Load time of the module */
    ULONG BaseNameHashValue;                          /**< Base name hash value of the module */
    ULONG ImplicitPathOptions;                        /**< Path options for implicit loading */
    ULONG ReferenceCount;                             /**< Reference count for the module */
    ULONG DependentLoadFlags;                         /**< Flags for dependent load */
    UCHAR SigningLevel;                               /**< Signing level for the module */
} LDR_DATA_TABLE_ENTRY;

/**
 * @brief Structure representing the state of an APC (Asynchronous Procedure Call).
 *
 * This structure holds the APC list heads and various flags that indicate the
 * current state of the APC within the process context.
 */
typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[MaximumMode];           /**< List heads for the APCs */
    struct _KPROCESS* Process;                     /**< Pointer to the process */
    union {
        UCHAR InProgressFlags;                     /**< Flags for in-progress APCs */
        struct {
            BOOLEAN KernelApcInProgress : 1;      /**< Flag for kernel APC in progress */
            BOOLEAN SpecialApcInProgress : 1;      /**< Flag for special APC in progress */
        };
    };

    BOOLEAN KernelApcPending;                      /**< Flag for pending kernel APCs */
    union {
        BOOLEAN UserApcPendingAll;                 /**< Flag for pending user APCs */
        struct {
            BOOLEAN SpecialUserApcPending : 1;     /**< Flag for special user APC pending */
            BOOLEAN UserApcPending : 1;             /**< Flag for user APC pending */
        };
    };
} KAPC_STATE, * PKAPC_STATE, * PRKAPC_STATE;

/**
 * @brief Process Environment Block (PEB) loader data structure.
 *
 * This structure contains information about the loading state of a process
 * and the status of various modules within the process.
 */
typedef struct {
    ULONG Length;                                /**< Length of the structure */
    UCHAR Initialized;                           /**< Initialization flag */
    VOID* SsHandle;                              /**< Handle for session state */
    struct _LIST_ENTRY InLoadOrderModuleList;     /**< List of modules in load order */
    struct _LIST_ENTRY InMemoryOrderModuleList;   /**< List of modules in memory order */
    struct _LIST_ENTRY InInitializationOrderModuleList; /**< List of modules in initialization order */
    VOID* EntryInProgress;                       /**< Entry progress indicator */
    UCHAR ShutdownInProgress;                    /**< Shutdown in progress flag */
    VOID* ShutdownThreadId;                      /**< Shutdown thread ID */
} PEB_LDR_DATA;
