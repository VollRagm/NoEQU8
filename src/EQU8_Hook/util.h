#pragma once

#include <stdlib.h>
#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>
#include <windef.h>
#include <ntimage.h>

#define PrintMessage( ... ) DbgPrintEx(0,0, "[NoEQU8] " __VA_ARGS__);

PVOID FindPatternImage(PCHAR base, PCHAR pattern, PCHAR mask);
PVOID GetKernelModuleByName(char* moduleName);
ULONG KeMessageBox(PCWSTR title, PCWSTR text, ULONG_PTR type);
NTSTATUS FindDriver(PDRIVER_OBJECT* DriverObject, PUNICODE_STRING DriverName);

extern "C" NTSTATUS NTAPI ExRaiseHardError(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask, PULONG_PTR Parameters, ULONG ValidResponseOptions, PULONG Response);

#define MB_ICONINFORMATION 0x40

extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(ULONG SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, ULONG* ReturnLength);

#define SystemModuleInformation 0xB

typedef struct _SYSTEM_MODULE
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _DEVICE_MAP* PDEVICE_MAP;

typedef struct _OBJECT_DIRECTORY_ENTRY
{
	_OBJECT_DIRECTORY_ENTRY* ChainLink;
	PVOID Object;
	ULONG HashValue;
} OBJECT_DIRECTORY_ENTRY, * POBJECT_DIRECTORY_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG NumberOfModules;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _OBJECT_DIRECTORY
{
	POBJECT_DIRECTORY_ENTRY HashBuckets[37];
	EX_PUSH_LOCK Lock;
	PDEVICE_MAP DeviceMap;
	ULONG SessionId;
	PVOID NamespaceEntry;
	ULONG Flags;
} OBJECT_DIRECTORY, * POBJECT_DIRECTORY;
