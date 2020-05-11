#define  _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <iostream>
#include <stdio.h>
#include "wow64ext.h"

/* [2020/05/11 20:35]-[Remark: None] */
/* [通过异常]-[Return:None] */
bool CheckDebug1()
{
	printf("CheckDebug1\n");
	__try
	{
		__asm    // 故意写一段会出异常的代码
		{
			pushfd
			or word ptr[esp], 0x100    // 令TF=1
			popfd
			nop
		}
	}
	__except (1)
	{
		return FALSE;    // 如果出异常说明没有被调试
	}
	return TRUE;    // 如果没有异常说明被OD等调试器接管了
}

/* [2020/05/11 20:31]-[Remark: None] */
/* [通过异常]-[Return:None] */
bool CheckDebug2()
{
	getchar();
	printf("CheckDebug2\n");
	HANDLE hTarget, hNewTarget;
	// 将当前进程的伪句柄转换为真实句柄赋值给hTarget
	DuplicateHandle((HANDLE)-1, (HANDLE)-1, (HANDLE)-1, &hTarget, 0, 0, DUPLICATE_SAME_ACCESS);
	// 设置句柄hTarget不允许被关闭
	SetHandleInformation(hTarget, HANDLE_FLAG_PROTECT_FROM_CLOSE, HANDLE_FLAG_PROTECT_FROM_CLOSE);
	// 故意关闭这个句柄制造异常
	DuplicateHandle((HANDLE)-1, (HANDLE)hTarget, (HANDLE)-1, &hNewTarget, 0, 0, DUPLICATE_CLOSE_SOURCE);
	// hNewTarget当被OD调试时为0,原因是SharpOD插件会强行给它赋值为0,
	// 其他没装SharpOD插件的OD则会直接崩溃, 但正常运行的可能输出0xD4或其它值
	printf("%08X", (DWORD)hNewTarget);
	if (hNewTarget == 0)
		return TRUE;
	return FALSE;
}

/* [2020/05/11 19:38]-[Remark: 由于访问不了64位地址,暂时用不了,待研究] */
/* [通过检测OD插件-SharpOD的Hook,判断是否在用OD调试]-[Return:None] */
bool CheckDebug3()
{
	// 需先导入wow64ext的h文件,lib文件,以及dll文件
	DWORD64 dwAddr = GetProcAddress64(GetModuleHandle64((wchar_t*)L"ntdll.dll"), (char*)"NtDuplicateObject");
	if (((PWORD)dwAddr)[0] == 0xFF25)    // 这里发现它访问不了这个地址,因为它已经超过32位
	{
		printf("检测到sharpOD插件\n");
		return TRUE;
	}
	else
	{
		printf("没有检测到sharpOD插件\n");
		return FALSE;
	}
}

/* [2020/05/11 20:29]-[Remark: 缺点是,当程序运行后再通过OD附加,无法检测] */
/* [通过检测OD对拖入的进程会CreateProcess,进而改变CommandLine]-[Return:None] */
bool __declspec(naked) CheckDebug4()
{
	__asm
	{
		mov eax, dword ptr fs : [0x18]			// 指向TEB结构体的指针
		mov eax, dword ptr ds : [eax + 0x30]	// 令eax 指向 PEB
		mov eax, dword ptr ds : [eax + 0x10]	// 令eax 指向 进程参数结构体
		mov edi, dword ptr ds : [eax + 0x44]	// edi = (UNICODE_STRING)CommandLine
		mov ecx, 0x100	// 计次ecx=0x100
		xor eax, eax	// eax=0
		repne scas word ptr es : [edi]	// 查找ecx次,直到[edi]==0x0000
		// 如果是直接启动的,这里是空格;如果是调试器启动,这里是引号0x22
		cmp word ptr ds : [edi - 0x4], 0x20	// 和 空格 作比较
	je NoDebug
		mov eax,0x1
		ret
	NoDebug:
		xor eax,eax
		ret
	}
}

int main()
{
	bool bRet = CheckDebug4();
	if (bRet)
	{
		printf("被调试");
	}
	else
	{
		printf("未被调试");
	}
	system("pause");
}

