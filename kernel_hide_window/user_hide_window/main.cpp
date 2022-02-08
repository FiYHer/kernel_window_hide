#include <windows.h>
#include <stdio.h>
#define HIDE_WINDOW CTL_CODE(FILE_DEVICE_UNKNOWN, 0x812, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _message64
{
	__int64 window_result;			// 执行结果
	__int64 window_handle;			// 窗口句柄
	int window_attributes;				// 窗口属性
}message64;

void simple()
{
	HANDLE h = CreateFileW(L"\\\\.\\hide_windows", GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (h == INVALID_HANDLE_VALUE) return;

	// 这里查找注册表的窗口
	HWND window_handle = FindWindowW(L"RegEdit_RegEdit", 0);
	if (window_handle)
	{
		/*
		查找了网上,发现WDA_EXCLUDEFROMCAPTURE标识在一些新版Win10上才有效果(变透明)
		在旧版Win10上表现为黑色窗口,这是没有办法的事情
		*/
		message64 info{ 0 };
		info.window_attributes = WDA_EXCLUDEFROMCAPTURE;
		info.window_handle = (__int64)window_handle;
		DeviceIoControl(h, HIDE_WINDOW, &info, sizeof(info), &info, sizeof(info), 0, 0);

		/*
		注意这里,就算上面设置了WDA_EXCLUDEFROMCAPTURE标识,但是这里也是返回0
		在一定作用上也能干扰下反作弊系统吧
		*/
		DWORD Style = 0;
		GetWindowDisplayAffinity(window_handle, &Style);
		printf("style is %d \n", Style);
	}

	CloseHandle(h);
}

int main(int argc, char* argv[])
{
	simple();
	system("pause");
	return 0;
}