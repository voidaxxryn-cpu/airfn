#pragma once
#include "../project_includes.hpp"
#include "../interrupts/interrupt_structs.hpp"
#include "../interrupts/interrupts.hpp"

#pragma pack(push, 1)
struct info_page_t {
	segment_descriptor_register_64 constructed_idt;
	segment_descriptor_register_64 user_idt_storage;
	uint64_t user_cr3_storage;
	uint64_t nmi_panic_function_storage;
};
#pragma pack(pop)

static_assert(offsetof(struct info_page_t, constructed_idt) == 0, "Offset");
static_assert(offsetof(struct info_page_t, user_idt_storage) == 0xA, "Offset");
static_assert(offsetof(struct info_page_t, user_cr3_storage) == 0x14, "Offset");
static_assert(offsetof(struct info_page_t, nmi_panic_function_storage) == 0x1C, "Offset");
static_assert(sizeof(struct info_page_t) == 0x24, "Size");

namespace shellcode {
	inline void* g_enter_constructed_space_executed = 0;
	inline void* g_enter_constructed_space_shown = 0;
	inline void* g_exit_constructed_space = 0;
	inline void* g_nmi_shellcode = 0;

	extern "C" info_page_t* g_info_page;

	inline void construct_executed_enter_shellcode(void* enter_constructed_space, void* orig_data_ptr_value, void* handler_address,
		uint64_t constructed_cr3, info_page_t* info_page_base) {

		static const uint8_t start_place_holder_shellcode[] = {
			0xFA,                                                       // cli
			0x0F, 0xAE, 0xF0,                                           // mfence
			0x81, 0xFA, 0x69, 0x69, 0x00, 0x00,                         // cmp edx, 0x6969
			0x74, 0x0D,                                                 // je skip_orig_function
			0xFB,                                                       // sti
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64
			0xFF, 0xE0,                                                 // jmp rax
		};

		static const uint8_t cr3_pushing_shellcode[] = {
			0x48, 0x0F, 0x20, 0xD8,                                     // mov rax, cr3
			0x50,                                                       // push rax
		};

		static const uint8_t cr3_changing_shellcode[] = {
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (constructed cr3)
			0x48, 0x0F, 0x22, 0xD8,                                     // mov cr3, rax
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64 (page addr)
			0x0F, 0x01, 0x38,
		};

		//AMD & Intel Support
		// used RDTSCP statt CPUID Leaf 0xB
		static const uint8_t calculate_base_shellcode[] = {
			0x53,                   // push rbx
			0x51,                   // push rcx
			0x52,                   // push rdx
			0x0F, 0x01, 0xF9,       // rdtscp (EDX:EAX = TSC, ECX = Processor ID)
			0x89, 0xC8,             // mov eax, ecx (Index nach EAX)
			0x5A,                   // pop rdx
			0x59,                   // pop rcx
			0x5B,                   // pop rbx
			0x48, 0x6B, 0xC0, 0x00, // imul rax, rax, sizeof(info_page_t) (Patch: +14)
			0x53,                   // push rbx
			0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, base (Patch: +18)
			0x48, 0x01, 0xD8,       // add rax, rbx
			0x5B,                   // pop rbx
			0x48, 0x8B, 0xD0,       // mov rdx, rax
		};

		static const uint8_t cr3_saving_shellcode[] = {
			0x52,                                                       // push rdx
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offset
			0x48, 0x8B, 0x54, 0x24, 0x08,                               // mov rdx, [rsp + 8]
			0x48, 0x89, 0x10,                                           // mov [rax], rdx
			0x5A,                                                       // pop rdx
			0x48, 0x83, 0xC4, 0x08,                                     // add rsp, 8
		};

		static const uint8_t nmi_panic_shellcode[] = {
			0x48, 0x8B, 0xC2,                                           // mov rax, rdx
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offset
			0x4C, 0x89, 0x00,                                           // mov [rax], r8
		};


		static const uint8_t jump_to_handler_shellcode[] = {
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64
			0xFF, 0xE0                                                  // jmp rax
		};

		// Patches
		*(void**)((uint8_t*)start_place_holder_shellcode + 15) = orig_data_ptr_value;
		*(uint64_t*)((uint8_t*)cr3_changing_shellcode + 2) = constructed_cr3;
		*(uint64_t*)((uint8_t*)cr3_changing_shellcode + 16) = (uint64_t)enter_constructed_space;

		// NEW OFFSETS for AMD FIX
		*(uint8_t*)((uint8_t*)calculate_base_shellcode + 14) = sizeof(info_page_t);
		*(void**)((uint8_t*)calculate_base_shellcode + 18) = info_page_base;

		*(uint8_t*)((uint8_t*)cr3_saving_shellcode + 4) = offsetof(info_page_t, user_cr3_storage);
		*(uint8_t*)((uint8_t*)nmi_panic_shellcode + 6) = offsetof(info_page_t, nmi_panic_function_storage);
		*(void**)((uint8_t*)jump_to_handler_shellcode + 2) = handler_address;

		// Construction
		uint8_t* current_position = (uint8_t*)enter_constructed_space;

		memcpy(current_position, start_place_holder_shellcode, sizeof(start_place_holder_shellcode));
		current_position += sizeof(start_place_holder_shellcode);
		memcpy(current_position, cr3_pushing_shellcode, sizeof(cr3_pushing_shellcode));
		current_position += sizeof(cr3_pushing_shellcode);
		memcpy(current_position, cr3_changing_shellcode, sizeof(cr3_changing_shellcode));
		current_position += sizeof(cr3_changing_shellcode);
		memcpy(current_position, calculate_base_shellcode, sizeof(calculate_base_shellcode));
		current_position += sizeof(calculate_base_shellcode);
		memcpy(current_position, cr3_saving_shellcode, sizeof(cr3_saving_shellcode));
		current_position += sizeof(cr3_saving_shellcode);
		memcpy(current_position, nmi_panic_shellcode, sizeof(nmi_panic_shellcode));
		current_position += sizeof(nmi_panic_shellcode);
		// memcpy(current_position, idt_shellcode, sizeof(idt_shellcode)); // activate may cause black screen...
		// current_position += sizeof(idt_shellcode);
		memcpy(current_position, jump_to_handler_shellcode, sizeof(jump_to_handler_shellcode));
	}

	inline void construct_shown_enter_shellcode(void* enter_constructed_space, void* orig_data_ptr_value, uint64_t constructed_cr3) {
		static const uint8_t start_place_holder_shellcode[] = {
			0xFA, 0x0F, 0xAE, 0xF0, 0x81, 0xFA, 0x69, 0x69, 0x00, 0x00, 0x74, 0x0D, 0xFB,
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0,
		};
		static const uint8_t cr3_pushing_shellcode[] = {
			0x48, 0x0F, 0x20, 0xD8, 0x50,
		};
		static const uint8_t cr3_changing_shellcode[] = {
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x0F, 0x22, 0xD8,
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x01, 0x38, 0x58,
		};
		static const uint8_t return_shellcode[] = { 0xC3 };

		*(void**)((uint8_t*)start_place_holder_shellcode + 15) = orig_data_ptr_value;
		*(uint64_t*)((uint8_t*)cr3_changing_shellcode + 2) = constructed_cr3;
		*(uint64_t*)((uint8_t*)cr3_changing_shellcode + 16) = (uint64_t)enter_constructed_space;

		uint8_t* current_position = (uint8_t*)enter_constructed_space;
		memcpy(current_position, start_place_holder_shellcode, sizeof(start_place_holder_shellcode));
		current_position += sizeof(start_place_holder_shellcode);
		memcpy(current_position, cr3_pushing_shellcode, sizeof(cr3_pushing_shellcode));
		current_position += sizeof(cr3_pushing_shellcode);
		memcpy(current_position, cr3_changing_shellcode, sizeof(cr3_changing_shellcode));
		current_position += sizeof(cr3_changing_shellcode);
		memcpy(current_position, return_shellcode, sizeof(return_shellcode));
		current_position += sizeof(return_shellcode);
	}

	inline void construct_exit_shellcode(void* exit_constructed_space, info_page_t* info_page_base) {
		// AMD & Intel Support
		static const uint8_t calculate_base_shellcode[] = {
			0x53,                   // push rbx
			0x51,                   // push rcx
			0x52,                   // push rdx
			0x0F, 0x01, 0xF9,       // rdtscp
			0x89, 0xC8,             // mov eax, ecx
			0x5A,                   // pop rdx
			0x59,                   // pop rcx
			0x5B,                   // pop rbx
			0x48, 0x6B, 0xC0, 0x00, // imul rax, rax, sizeof(info_page_t) (+14)
			0x53,                   // push rbx
			0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, base (+18)
			0x48, 0x01, 0xD8,       // add rax, rbx
			0x5B,                   // pop rbx
			0x48, 0x8B, 0xD0,       // mov rdx, rax
		};

		static const uint8_t restore_cr3_shellcode[] = {
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offset
			0x48, 0x8B, 0x00,                                           // mov rax, [rax]
			0x0F, 0x22, 0xD8,                                           // mov cr3, rax
		};


		static const uint8_t return_shellcode[] = { 0xC3 };

		*(uint8_t*)((uint8_t*)calculate_base_shellcode + 14) = sizeof(info_page_t);
		*(void**)((uint8_t*)calculate_base_shellcode + 18) = info_page_base;

		*(uint8_t*)((uint8_t*)restore_cr3_shellcode + 3) = offsetof(info_page_t, user_cr3_storage);

		uint8_t* current_position = (uint8_t*)exit_constructed_space;
		memcpy(current_position, calculate_base_shellcode, sizeof(calculate_base_shellcode));
		current_position += sizeof(calculate_base_shellcode);
		memcpy(current_position, restore_cr3_shellcode, sizeof(restore_cr3_shellcode));
		current_position += sizeof(restore_cr3_shellcode);
		// memcpy(current_position, restore_idt_shellcode, sizeof(restore_idt_shellcode)); // DISABLED
		// current_position += sizeof(restore_idt_shellcode);
		memcpy(current_position, return_shellcode, sizeof(return_shellcode));
		current_position += sizeof(return_shellcode);
	}

	inline void construct_nmi_shellcode(void* nmi_shellcode, info_page_t* info_page_base, void* windows_nmi_handler) {
		// FIX: AMD & Intel Support (Universal)
		static const uint8_t calculate_base_shellcode[] = {
			0x53,                   // push rbx
			0x51,                   // push rcx
			0x52,                   // push rdx
			0x0F, 0x01, 0xF9,       // rdtscp
			0x89, 0xC8,             // mov eax, ecx
			0x5A,                   // pop rdx
			0x59,                   // pop rcx
			0x5B,                   // pop rbx
			0x48, 0x6B, 0xC0, 0x00, // imul rax, rax, sizeof (+14)
			0x53,                   // push rbx
			0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rbx, base (+18)
			0x48, 0x01, 0xD8,       // add rax, rbx
			0x5B,                   // pop rbx
			0x48, 0x8B, 0xD0,       // mov rdx, rax
		};

		static const uint8_t restore_cr3_shellcode[] = {
			0x48, 0x8B, 0xC2,                                           // mov rax, rdx
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offset
			0x48, 0x8B, 0x00,                                           // mov rax, [rax]
			0x0F, 0x22, 0xD8,                                           // mov cr3, rax
		};


		static const uint8_t panic_or_windows_shellcode[] = {
			0x48, 0x8B, 0xC2,                                           // mov rax, rdx
			0x48, 0x83, 0xC0, 0x00,                                     // add rax, offset
			0x48, 0x8B, 0x00,                                           // mov rax, [rax]
			0x48, 0x85, 0xC0,                                           // test rax, rax
			0x74, 0x02,                                                 // je +2
			0xFF, 0xE0,                                                 // jmp rax
			0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, imm64
			0xFF, 0xE0,                                                 // jmp rax
		};

		*(uint8_t*)((uint8_t*)calculate_base_shellcode + 14) = sizeof(info_page_t);
		*(void**)((uint8_t*)calculate_base_shellcode + 18) = info_page_base;

		*(uint8_t*)((uint8_t*)restore_cr3_shellcode + 4) = offsetof(info_page_t, user_cr3_storage);
		*(uint8_t*)((uint8_t*)panic_or_windows_shellcode + 4) = offsetof(info_page_t, nmi_panic_function_storage);
		*(void**)((uint8_t*)panic_or_windows_shellcode + 18) = windows_nmi_handler;

		uint8_t* current_position = (uint8_t*)nmi_shellcode;
		memcpy(current_position, calculate_base_shellcode, sizeof(calculate_base_shellcode));
		current_position += sizeof(calculate_base_shellcode);
		memcpy(current_position, restore_cr3_shellcode, sizeof(restore_cr3_shellcode));
		current_position += sizeof(restore_cr3_shellcode);
		// memcpy(current_position, restore_idt_shellcode, sizeof(restore_idt_shellcode)); // DISABLED
		// current_position += sizeof(restore_idt_shellcode);
		memcpy(current_position, panic_or_windows_shellcode, sizeof(panic_or_windows_shellcode));
		current_position += sizeof(panic_or_windows_shellcode);
	}

	inline project_status construct_shellcodes(void*& enter_constructed_space_executed, void*& enter_constructed_space_shown, void*& exit_constructed_space, void*& nmi_shellcode,
		segment_descriptor_register_64 my_idt_ptr,
		void* orig_data_ptr_value, void* handler_address,
		uint64_t constructed_cr3) {

		PHYSICAL_ADDRESS max_addr = { 0 };
		info_page_t* info_page = 0;
		max_addr.QuadPart = MAXULONG64;

		enter_constructed_space_executed = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		enter_constructed_space_shown = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		exit_constructed_space = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		nmi_shellcode = MmAllocateContiguousMemory(PAGE_SIZE, max_addr);
		info_page = (info_page_t*)MmAllocateContiguousMemory(KeQueryActiveProcessorCount(0) * sizeof(info_page_t), max_addr);

		if (!enter_constructed_space_executed || !enter_constructed_space_shown
			|| !exit_constructed_space || !info_page) {
			return status_memory_allocation_failed;
		}

		memset(enter_constructed_space_executed, 0, PAGE_SIZE);
		memset(enter_constructed_space_shown, 0, PAGE_SIZE);
		memset(exit_constructed_space, 0, PAGE_SIZE);
		memset(nmi_shellcode, 0, PAGE_SIZE);
		memset(info_page, 0, KeQueryActiveProcessorCount(0) * sizeof(info_page_t));

		for (uint32_t i = 0; i < KeQueryActiveProcessorCount(0); i++) {
			info_page[i].constructed_idt = my_idt_ptr;
			info_page[i].nmi_panic_function_storage = 0;
		}

		construct_executed_enter_shellcode(enter_constructed_space_executed, orig_data_ptr_value, handler_address, constructed_cr3, info_page);
		construct_shown_enter_shellcode(enter_constructed_space_shown, orig_data_ptr_value, constructed_cr3);
		construct_exit_shellcode(exit_constructed_space, info_page);
		construct_nmi_shellcode(nmi_shellcode, info_page, interrupts::get_windows_nmi_handler());

		g_enter_constructed_space_executed = enter_constructed_space_executed;
		g_enter_constructed_space_shown = enter_constructed_space_shown;
		g_exit_constructed_space = exit_constructed_space;
		g_nmi_shellcode = nmi_shellcode;
		g_info_page = info_page;

		return status_success;
	}

	inline uint64_t get_current_user_cr3(void) {
		return g_info_page[get_proc_number()].user_cr3_storage;
	}

	inline uint64_t get_current_nmi_panic_function(void) {
		return g_info_page[get_proc_number()].nmi_panic_function_storage;
	}
};