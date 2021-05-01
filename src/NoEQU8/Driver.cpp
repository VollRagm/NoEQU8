#include "Driver.h"

NTSTATUS ReadProcessId(int* processId)
{
	//		<ghetto code>

	UNICODE_STRING filepath = { 0 };
	OBJECT_ATTRIBUTES fileObj = { 0 };

	RtlInitUnicodeString(&filepath, L"\\DosDevices\\C:\\pid.txt");
	InitializeObjectAttributes(&fileObj, &filepath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);

	HANDLE fileHandle = 0;
	IO_STATUS_BLOCK ioStatusBlock;

	auto status = ZwCreateFile(&fileHandle, GENERIC_READ, &fileObj,
								&ioStatusBlock, nullptr, FILE_ATTRIBUTE_NORMAL, 
								0, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, nullptr, 0);
	
	if (!NT_SUCCESS(status))
	{
		KeMessageBox(L"Error", L"Could not open C:\\pid.txt. Check Dbgview for more information.", MB_ICONINFORMATION);
		PrintMessage("ZwCreateFile failed -> %lx\n", status);
		return status;
	}

	CHAR buffer[11];

	status = ZwReadFile(fileHandle, nullptr, nullptr, nullptr,
						&ioStatusBlock, buffer, sizeof(buffer),
						nullptr, nullptr);

	if (!NT_SUCCESS(status))
	{
		ZwClose(fileHandle);
		KeMessageBox(L"Error", L"Could not read C:\\pid.txt. Check Dbgview for more information.", MB_ICONINFORMATION);
		PrintMessage("ZwReadFile failed -> %lx\n", status);
		return status;
	}

	buffer[10] = '\0';
	
	ZwClose(fileHandle);
	
	ANSI_STRING pidString = { 0 };
	UNICODE_STRING pidUString{ 0 };
	RtlInitAnsiString(&pidString, buffer);
	RtlAnsiStringToUnicodeString(&pidUString, &pidString, TRUE);

	ULONG pid = 0;
	status = RtlUnicodeStringToInteger(&pidUString, 10, &pid);

	RtlFreeUnicodeString(&pidUString);
	

	if (!NT_SUCCESS(status))
	{
		KeMessageBox(L"Error", L"Could not parse C:\\pid.txt. Check Dbgview for more information.", MB_ICONINFORMATION);
		PrintMessage("RtlUnicodeStringToInteger blew up -> %lx\n", status);
		return status;
	}

	*processId = pid;
	
	PrintMessage("Successfully read process id -> %lx\n", pid);

	//		</ghetto code>

	return status;
}

ULONG64 ResolveInstructionOffset(PCHAR instruction, ULONG64 offsetToEIP, ULONG64 offsetOfDataPtr)
{
	ULONG64 EIP = (ULONG64)instruction + offsetToEIP;	//instruction pointer to add offset to
	LONG32 offset = *(LONG32*)(instruction + offsetOfDataPtr);	//get the data ptr offset from the current EIP
	return EIP + offset;
}


NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	PrintMessage("Driver Loaded.");

	int processId = 0;
	auto status = ReadProcessId(&processId);

	if (!NT_SUCCESS(status))
		return status;

	//getting the module base address of the AC driver module
	PVOID equ8Base = GetKernelModuleByName("EQU8_");

	if (!equ8Base)
	{
		KeMessageBox(L"Error", L"Could not find EQU8 Anticheat.", MB_ICONINFORMATION);
		PrintMessage("Could not find EQU8 Anticheat module :(\n");
		return STATUS_UNSUCCESSFUL;
	}

	PrintMessage("Located EQU8 -> %p\n", equ8Base);
	
	PCHAR hans_peter_ludwig = (PCHAR)FindPatternImage((PCHAR)equ8Base, "\x8B\x17\xE8\x00\x00\x00\x00\xEB\x71", "xxx????xx");

	if (!hans_peter_ludwig)
	{
		KeMessageBox(L"Error", L"Could not find function address.", MB_ICONINFORMATION);
		PrintMessage("Could not find function address.\n");
		return STATUS_UNSUCCESSFUL;
	}

	PVOID functionAddress = (PVOID)ResolveInstructionOffset(hans_peter_ludwig, 7, 3);
	PrintMessage("AddTrustedProcessById -> %p", functionAddress);

	PCHAR mareike_meier = (PCHAR)FindPatternImage((PCHAR)equ8Base, "\x48\x8D\x0D\x00\x00\x00\x00\xEB\x2D", "xxx????xx");

	if (!mareike_meier)
	{
		KeMessageBox(L"Error", L"Could not find trusted process list.", MB_ICONINFORMATION);
		PrintMessage("Could not find trusted process list.\n");
		return STATUS_UNSUCCESSFUL;
	}

	PVOID trustedProcessList = (PVOID)ResolveInstructionOffset(mareike_meier, 7, 3);

	EQ_AddTrustedProcessById_t EQ_AddTrustedProcessById = (EQ_AddTrustedProcessById_t)functionAddress;
	auto nt_status = EQ_AddTrustedProcessById(trustedProcessList, processId);

	if (NT_SUCCESS(nt_status))
	{
		KeMessageBox(L"Info", L"Process whitelisted successfully!", MB_ICONINFORMATION);
		PrintMessage("Added process to the whitelist.");
	}
	else
	{
		KeMessageBox(L"Error", L"Process could not be whitelisted. Check Dbgview for further information.", MB_ICONINFORMATION);
		PrintMessage("Unable to whitelist process, AddTrustedProcessById -> %lx\n", status);
	}

	return STATUS_SUCCESS;
}