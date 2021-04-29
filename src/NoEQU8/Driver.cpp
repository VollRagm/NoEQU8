#include "Driver.h"

ULONG64 GetDataPtr(PCHAR instruction)
{
	ULONG64 EIP = (ULONG64)instruction + 12;	//instruction pointer to add offset to
	ULONG32 offset = *(ULONG32*)(instruction + 8);	//get the data ptr offset from the current EIP
	return EIP + offset;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	//getting the module base address of the AC driver module
	PVOID equ8Base = GetKernelModuleByName("EQU8_");

	if (!equ8Base)
	{
		PrintMessage("Could not find EQU8 Anticheat module :(");
		KeMessageBox(L"Error", L"Could not disable EQU8, check Dbgview for further information.", MB_ICONINFORMATION);
		return STATUS_UNSUCCESSFUL;
	}

	PrintMessage("Located EQU8 -> %p\n", equ8Base);

	//scan images .text section for the target instruction
	PVOID instruction = FindPatternImage((PCHAR)equ8Base, "\x33\xFF\x48\x8B\xDA\x40\x38\x3D\x00\x00\x00\x00\x0F\x84\x00\x00\x00\x00", "xxxxxxxx????xx????");

	if (!instruction)
	{
		PrintMessage("Unable to find target instruction!");
		KeMessageBox(L"Error", L"Could not disable EQU8, check Dbgview for further information.", MB_ICONINFORMATION);
		return STATUS_UNSUCCESSFUL;
	}

	PrintMessage("Located target instruction -> %p\n", instruction);

	PBOOL IsACEnabledPtr = (PBOOL)GetDataPtr((PCHAR)instruction);

	PrintMessage("Global variable located -> %p\n", IsACEnabledPtr);

	*IsACEnabledPtr = 0;	//disable the checks entirely

	PrintMessage("Anitcheat disabled.");
	KeMessageBox(L"Success", L"EQU8 disabled successfully.", MB_ICONINFORMATION);

	return STATUS_SUCCESS;
}