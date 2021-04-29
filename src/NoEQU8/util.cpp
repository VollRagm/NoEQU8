#include "util.h"

ULONG KeMessageBox(PCWSTR title, PCWSTR text, ULONG_PTR type)
{
	UNICODE_STRING u_title = { 0 };
	UNICODE_STRING u_text = { 0 };

	RtlInitUnicodeString(&u_title, title);
	RtlInitUnicodeString(&u_text, text);

	ULONG_PTR args[] = { (ULONG_PTR)&u_text, (ULONG_PTR)&u_title, type };
	ULONG response = 0;

	ExRaiseHardError(STATUS_SERVICE_NOTIFICATION, 3, 3, args, 1, &response);
	return response;
}

PVOID GetKernelModuleByName(char* moduleName)
{
	ULONG poolSize = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, 0, &poolSize); //get the estimated size first
	
	if (status != STATUS_INFO_LENGTH_MISMATCH)	//thats normal, it will return the required pool size anyways
	{
		PrintMessage("ZwQuerySystemInformation failed!");
		return 0;
	}

	auto sysModInfo = (SYSTEM_MODULE_INFORMATION*)ExAllocatePool(NonPagedPool, poolSize);

	if (!sysModInfo)
	{
		PrintMessage("Unable to allocate pool!");
		return 0;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation, sysModInfo, poolSize, nullptr);
	
	if (!NT_SUCCESS(status))
	{
		PrintMessage("ZwQuerySystemInformation failed! -> %lx", status);
		ExFreePool(sysModInfo);
		return 0;
	}

	PVOID address = 0;

	for (unsigned int i = 0; i < sysModInfo->NumberOfModules; i++)
	{
		auto moduleEntry = sysModInfo->Modules[i];

		if (strstr((char*)moduleEntry.FullPathName, moduleName))
		{
			address = moduleEntry.ImageBase;
		}
	}

	ExFreePool(sysModInfo);
	return address;
}

//the following 3 functions have kindly been gathered from https://github.com/btbd/hwid/blob/master/Kernel/util.c
BOOL CheckMask(PCHAR base, PCHAR pattern, PCHAR mask)
{
	for (; *mask; ++base, ++pattern, ++mask)
	{
		if ('x' == *mask && *base != *pattern)
		{
			return FALSE;
		}
	}

	return TRUE;
}

PVOID FindPattern(PCHAR base, DWORD length, PCHAR pattern, PCHAR mask)
{
	length -= (DWORD)strlen(mask);
	for (DWORD i = 0; i <= length; ++i)
	{
		PVOID addr = &base[i];
		if (CheckMask((PCHAR)addr, pattern, mask))
		{
			return addr;
		}
	}

	return 0;
}

PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask)
{
	PVOID match = 0;

	PIMAGE_NT_HEADERS headers = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(headers);
	for (DWORD i = 0; i < headers->FileHeader.NumberOfSections; ++i)
	{
		PIMAGE_SECTION_HEADER section = &sections[i];
		if (memcmp(section->Name, ".text", 5) == 0)
		{
			match = FindPattern(base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (match)
			{
				break;
			}
		}
	}

	return match;
}