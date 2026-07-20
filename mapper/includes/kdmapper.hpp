#pragma once

#include <Windows.h>

namespace kdmapper
{
	enum class AllocationMode
	{
		AllocatePool,
		AllocateIndependentPages,
		AllocateContiguousMemory
	};

	typedef bool (*mapCallback)(ULONG64* param1, ULONG64* param2, ULONG64 allocationPtr, ULONG64 allocationSize);

	//Note: if you set PassAllocationAddressAsFirstParam as true, param1 will be ignored
	ULONG64 MapDriver(BYTE* data, ULONG64 param1, ULONG64 param2, bool free, bool remove_from_system_page_tables, bool destroyHeader, AllocationMode mode, bool PassAllocationAddressAsFirstParam, bool PassSizeAsSecondParam, mapCallback callback, NTSTATUS* exitCode);
}