// Template
// Module copying needs to be implemented
// jasonfish4

#include <ntifs.h>
#include <ntdef.h>
#include <wdf.h>
#include "PeImg.h"

#define MAIN_SIGOFF 0 // Signature offset in need of implementation
#define NT_SIGOFF 1 // Signature offset in need of implementation
#define MAIN_SIG 2 // Signature offset in need of implementation
#define NT_SIG 3 // Signature offset in need of implementation

DRIVER_INITIALIZE DriverEntry;
PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev;

DWORD_PTR signature_offset;
DWORD_PTR image_base;
DWORD_PTR process_id;
PDWORD_PTR userthreadstart_callback;
PDWORD_PTR userthreadstart_codecave;
IMPORT_ADDRESS_TABLE import_address_table;

BYTE userthread_hook[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 }; // jmp address 

BYTE userthread_hook_method[] = {
	0x2B, 0x05, 0x00, 0x00, 0x00, 0x00, // sub eax, [address]
	0x03, 0x05, 0x00, 0x00, 0x00, 0x00, // add eax, [address]
	0x89, 0x44, 0x24, 0x04,             // mov [esp+04],eax
	0x89, 0x5C, 0x24, 0x08,             // mov [esp+08],ebx
	0xE9, 0x00, 0x00, 0x00, 0x00        // jmp address
};


BOOLEAN CheckSignature64(DWORD_PTR SignatureAddress, DWORD64 Signature)
{
	__try
	{
		ProbeForRead(SignatureAddress, sizeof(DWORD64), TYPE_ALIGNMENT(char));
		if (RtlCompareMemory(SignatureAddress, &Signature, sizeof(DWORD64)) == sizeof(DWORD64))
			return TRUE;
		else
			return FALSE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Signature access failed - exception");
		return FALSE;
	}
}

void SetProtection(PMDL* MdlArray, SIZE_T MdlArraySize, LONG Protection)
{
	for (SIZE_T mdl = 0; mdl < MdlArraySize; mdl++)
		MmProtectMdlSystemAddress(MdlArray[mdl], Protection);
}

void ProbeLockPagesUser(PMDL* MdlArray, SIZE_T MdlArraySize, BOOLEAN Lock)
{
	if (Lock)
	{
		for (SIZE_T mdl = 0; mdl < MdlArraySize; mdl++)
			MmProbeAndLockPages(MdlArray[mdl], UserMode, IoReadAccess);
	}
	else
	{
		for (SIZE_T mdl = 0; mdl < MdlArraySize; mdl++)
			MmUnlockPages(MdlArray[mdl]);
	}
}

VOID GetImportAddressTable(PVOID ModuleBase)
{
	PUSERMODE_IMAGE_HEADER virtual_process_info = (PUSERMODE_IMAGE_HEADER)ModuleBase;
	PUSERMODE_NT_HEADER virtual_process_nt = (PUSERMODE_NT_HEADER)((BYTE*)virtual_process_info + 
		virtual_process_info->e_lfanew);

	import_address_table.Size = virtual_process_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size;
	import_address_table.Address = (PVOID)((DWORD32)virtual_process_info + 
		virtual_process_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress);
}

VOID ProcessLoadImageCallback(_In_opt_ PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo)
{
	DWORD64 comparator;

	if (!process_id)
	{
		signature_offset = MAIN_SIGOFF;
		comparator = MAIN_SIG;
	}
	else
	{
		signature_offset = NT_SIGOFF;
		comparator = NT_SIG;
	}
	
	if (!CheckSignature64((PDWORD_PTR)((DWORD_PTR)ImageInfo->ImageBase + signature_offset), comparator))
	{
		DbgPrint("Signature not found");
		return;
	}

	if (!process_id)
	{
		GetImportAddressTable(ImageInfo->ImageBase);
		image_base = (DWORD_PTR)ImageInfo->ImageBase;
		process_id = (DWORD_PTR)ProcessId;
		return;
	}

	PMDL descriptor_array[2];
	descriptor_array[0] = IoAllocateMdl(userthreadstart_callback, sizeof(userthread_hook), FALSE, FALSE, NULL);
	descriptor_array[1] = IoAllocateMdl(userthreadstart_codecave, sizeof(userthread_hook_method), FALSE, FALSE, NULL);

	__try
	{
		ProbeLockPagesUser(descriptor_array, 2, TRUE);
		SetProtection(descriptor_array, 2, PAGE_EXECUTE_READWRITE);

		DWORD_PTR jmp_codecave_callback = (userthreadstart_codecave - userthreadstart_callback) - 5;
		DWORD_PTR jmp_callback = (userthreadstart_callback - userthreadstart_codecave) - 5;

		RtlCopyMemory(&userthread_hook[1], &jmp_codecave_callback, 4);
		RtlCopyMemory(&userthread_hook_method[21], &jmp_callback, 4);
		RtlCopyMemory((PVOID)userthreadstart_callback, &userthread_hook, sizeof(userthread_hook));
		RtlCopyMemory((PVOID)userthreadstart_codecave, &userthread_hook_method, sizeof(userthread_hook_method));

		SetProtection(descriptor_array, 2, PAGE_EXECUTE_READ);
		ProbeLockPagesUser(descriptor_array, 2, FALSE);
		IoFreeMdl(descriptor_array[0]);
		IoFreeMdl(descriptor_array[1]);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Access violation occurred while probing and locking pages");
		return;
	}
}

VOID WorkThread(IN PVOID pContext)
{
	PsSetLoadImageNotifyRoutine(ProcessLoadImageCallback);
	// Wait State Code needs to be implemented as well as signals
	PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	PsRemoveLoadImageNotifyRoutine(ProcessLoadImageCallback);
	IoDeleteDevice(pDriverObject->DeviceObject);
	return 0;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	WDF_DRIVER_CONFIG config;
	IoCreateDevice(DriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

	HANDLE hControl;
	status = PsCreateSystemThread(&hControl, (ACCESS_MASK)0, NULL, NULL, NULL, WorkThread, NULL);

	if (!NT_SUCCESS(status))
		return status;

	ZwClose(hControl);
	DriverObject->DriverUnload = UnloadDriver;
	return STATUS_SUCCESS;
}
