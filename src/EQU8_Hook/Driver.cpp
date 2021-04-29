#include "Driver.h"

#define DEVICE_NAME_OFFSET 0x3078

PDRIVER_DISPATCH OriginalDispatch = 0;

NTSTATUS DeviceControlHook(PDEVICE_OBJECT device, PIRP irp)
{
	auto IoStackLocation = IoGetCurrentIrpStackLocation(irp);
	PrintMessage("CTL_CODE: %lx", IoStackLocation->Parameters.DeviceIoControl.IoControlCode);

	auto IoStatus = OriginalDispatch(device, irp);
	auto IrpInfo = irp->IoStatus.Information;

	PrintMessage("Return value: IoStatus= %lx | IrpInfo= %llx", IoStatus, IrpInfo);

	return IoStatus;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	//getting the module base address of the AC driver module
	ULONG64 equ8Base = (ULONG64)GetKernelModuleByName("EQU8_");

	if (!equ8Base)
	{
		PrintMessage("Could not find EQU8 Anticheat module :(");
		return STATUS_UNSUCCESSFUL;
	}
	
	PrintMessage("Located EQU8 -> %llx\n", equ8Base);

	UNICODE_STRING driverName = { 0 };
	RtlInitUnicodeString(&driverName, L"\\Driver\\EQU8_HELPER_19");

	PDRIVER_OBJECT driverObject = 0;
	
	auto status = FindDriver(&driverObject, &driverName);
	
	PrintMessage("Driver name -> %wZ | Address: %p", &driverName, driverObject);

	

	if (!NT_SUCCESS(status))
	{
		PrintMessage("FindDriver failed! -> %lx", status);
		return STATUS_UNSUCCESSFUL;
	}

	OriginalDispatch = driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
	driverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PDRIVER_DISPATCH)DeviceControlHook;

	PrintMessage("Swapped DeviceControl");

	return STATUS_SUCCESS;
}