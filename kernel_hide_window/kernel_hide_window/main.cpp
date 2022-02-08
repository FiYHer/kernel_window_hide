#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>

#define HIDE_WINDOW CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

UNICODE_STRING g_device_name = RTL_CONSTANT_STRING(L"\\Device\\hide_windows");
UNICODE_STRING g_symbolic_link = RTL_CONSTANT_STRING(L"\\DosDevices\\hide_windows");
PDEVICE_OBJECT g_device_object = nullptr;

typedef __int64(__fastcall* FChangeWindowTreeProtection)(void* a1, int a2);
FChangeWindowTreeProtection g_ChangeWindowTreeProtection = 0;

typedef __int64(__fastcall* FValidateHwnd)(__int64 a1);
FValidateHwnd g_ValidateHwnd = 0;

typedef struct _message64
{
	__int64 window_result;			// 执行结果
	__int64 window_handle;			// 窗口句柄
	int window_attributes;				// 窗口属性
}message64;

#ifdef __cplusplus
extern "C"
{
#endif

	typedef struct _SYSTEM_MODULE
	{
		ULONG_PTR Reserved[2];
		PVOID Base;
		ULONG Size;
		ULONG Flags;
		USHORT Index;
		USHORT Unknown;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		CHAR ImageName[256];
	} SYSTEM_MODULE, * PSYSTEM_MODULE;

	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG_PTR ulModuleCount;
		SYSTEM_MODULE Modules[1];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineName);

	NTSTATUS
		NTAPI
		ZwQuerySystemInformation(
			DWORD32 systemInformationClass,
			PVOID systemInformation,
			ULONG systemInformationLength,
			PULONG returnLength);

#ifdef __cplusplus
}
#endif

// 获取模块基址
bool get_module_base_address(const char* name, unsigned long long& addr, unsigned long& size)
{
	unsigned long need_size = 0;
	ZwQuerySystemInformation(11, &need_size, 0, &need_size);
	if (need_size == 0) return false;

	const unsigned long tag = 'VMON';
	PSYSTEM_MODULE_INFORMATION sys_mods = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, need_size, tag);
	if (sys_mods == 0) return false;

	NTSTATUS status = ZwQuerySystemInformation(11, sys_mods, need_size, 0);
	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(sys_mods, tag);
		return false;
	}

	for (unsigned long long i = 0; i < sys_mods->ulModuleCount; i++)
	{
		PSYSTEM_MODULE mod = &sys_mods->Modules[i];
		if (strstr(mod->ImageName, name))
		{
			addr = (unsigned long long)mod->Base;
			size = (unsigned long)mod->Size;
			break;
		}
	}

	ExFreePoolWithTag(sys_mods, tag);
	return true;
}

// 模式匹配
bool pattern_check(const char* data, const char* pattern, const char* mask)
{
	size_t len = strlen(mask);

	for (size_t i = 0; i < len; i++)
	{
		if (data[i] == pattern[i] || mask[i] == '?')
			continue;
		else
			return false;
	}

	return true;
}
unsigned long long find_pattern(unsigned long long addr, unsigned long size, const char* pattern, const char* mask)
{
	size -= (unsigned long)strlen(mask);

	for (unsigned long i = 0; i < size; i++)
	{
		if (pattern_check((const char*)addr + i, pattern, mask))
			return addr + i;
	}

	return 0;
}
unsigned long long find_pattern_image(unsigned long long addr, const char* pattern, const char* mask)
{
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)addr;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return 0;

	PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(addr + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return 0;

	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);

	for (unsigned short i = 0; i < nt->FileHeader.NumberOfSections; i++)
	{
		PIMAGE_SECTION_HEADER p = &section[i];

		if (strstr((const char*)p->Name, ".text") || 'EGAP' == *reinterpret_cast<int*>(p->Name))
		{
			unsigned long long res = find_pattern(addr + p->VirtualAddress, p->Misc.VirtualSize, pattern, mask);
			if (res) return res;
		}
	}

	return 0;
}

// 获取导出函数
void* get_system_base_export(const char* module_name, const char* routine_name)
{
	unsigned long long win32kbase_address = 0;
	unsigned long win32kbase_length = 0;
	get_module_base_address(module_name, win32kbase_address, win32kbase_length);
	DbgPrintEx(0, 0, "[+] %s base address is 0x%llX \n", module_name, win32kbase_address);
	if (MmIsAddressValid((void*)win32kbase_address) == FALSE) return 0;

	return RtlFindExportedRoutineByName((void*)win32kbase_address, routine_name);
}

// 初始化
bool initialize()
{
	unsigned long long win32kfull_address = 0;
	unsigned long win32kfull_length = 0;
	get_module_base_address("win32kfull.sys", win32kfull_address, win32kfull_length);
	DbgPrintEx(0, 0, "[+] win32kfull base address is 0x%llX \n", win32kfull_address);
	if (MmIsAddressValid((void*)win32kfull_address) == FALSE) return false;

	/*
	call    ?ChangeWindowTreeProtection@@YAHPEAUtagWND@@H@Z ; ChangeWindowTreeProtection(tagWND *,int)
	mov     esi, eax
	test    eax, eax
	jnz     short loc_1C0245002
	*/
	unsigned long long address = find_pattern_image(win32kfull_address,
		"\xE8\x00\x00\x00\x00\x8B\xF0\x85\xC0\x75\x00\x44\x8B\x44",
		"x????xxxxx?xxx");
	DbgPrintEx(0, 0, "[+] pattern address is 0x%llX \n", address);
	if (address == 0) return false;

	// 5=汇编指令长度
	// 1=偏移
	g_ChangeWindowTreeProtection = reinterpret_cast<FChangeWindowTreeProtection>(reinterpret_cast<char*>(address) + 5 + *reinterpret_cast<int*>(reinterpret_cast<char*>(address) + 1));
	DbgPrintEx(0, 0, "[+] ChangeWindowTreeProtection address is 0x%p \n", g_ChangeWindowTreeProtection);
	if (MmIsAddressValid(g_ChangeWindowTreeProtection) == FALSE) return false;

	g_ValidateHwnd = (FValidateHwnd)get_system_base_export("win32kbase.sys", "ValidateHwnd");
	DbgPrintEx(0, 0, "[+] ValidateHwnd address is 0x%p \n", g_ValidateHwnd);
	if (MmIsAddressValid(g_ValidateHwnd) == FALSE) return false;

	return true;
}

// 修改窗口状态
__int64 change_window_attributes(__int64 handler, int attributes)
{
	if (MmIsAddressValid(g_ChangeWindowTreeProtection) == FALSE) return 0;
	if (MmIsAddressValid(g_ValidateHwnd) == FALSE) return 0;

	void* wnd_ptr = (void*)g_ValidateHwnd(handler);
	if (MmIsAddressValid(wnd_ptr) == FALSE) return 0;

	return g_ChangeWindowTreeProtection(wnd_ptr, attributes);
}

// 创建设备
NTSTATUS create_device(PDRIVER_OBJECT driver)
{
	NTSTATUS status = IoCreateDevice(driver, 0, &g_device_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_device_object);
	if (!NT_SUCCESS(status))
		return status;

	status = IoCreateSymbolicLink(&g_symbolic_link, &g_device_name);
	if (!NT_SUCCESS(status))
	{
		IoDeleteDevice(g_device_object);
		return status;
	}

	g_device_object->Flags |= DO_DIRECT_IO;
	g_device_object->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}

// 释放设备
void release_device()
{
	if (g_device_object != nullptr)
	{
		IoDeleteSymbolicLink(&g_symbolic_link);
		IoDeleteDevice(g_device_object);
		g_device_object = nullptr;
	}
}

// 默认irp处理例程
NTSTATUS defalut_irp(PDEVICE_OBJECT device, PIRP irp)
{
	UNREFERENCED_PARAMETER(device);

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// 通信irp处理例程
NTSTATUS communication_irp(PDEVICE_OBJECT device, PIRP irp)
{
	UNREFERENCED_PARAMETER(device);

	PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(irp);
	ULONG control = io->Parameters.DeviceIoControl.IoControlCode;
	message64* info = (message64*)irp->AssociatedIrp.SystemBuffer;

	if (control == HIDE_WINDOW && MmIsAddressValid(info))
	{
		// 初始化
		static bool init = false;
		if (!init) init = initialize();

		info->window_result = change_window_attributes(info->window_handle, info->window_attributes);
	}

	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

// 驱动卸载例程
VOID DriverUnload(PDRIVER_OBJECT driver_object)
{
	UNREFERENCED_PARAMETER(driver_object);

	// 关闭通信设备
	release_device();
}

// 驱动入口函数
EXTERN_C
NTSTATUS
DriverEntry(
	PDRIVER_OBJECT driver_object,
	PUNICODE_STRING registry_path)
{
	// 移除警告
	UNREFERENCED_PARAMETER(registry_path);

	// 设置卸载函数
	driver_object->DriverUnload = DriverUnload;

	// 创建通信设备
	NTSTATUS status = create_device(driver_object);
	if (!NT_SUCCESS(status))
		return status;

	// 设置全部派遣例程为默认
	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		driver_object->MajorFunction[i] = defalut_irp;

	// 设置通信派遣函数
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = communication_irp;

	return status;
}