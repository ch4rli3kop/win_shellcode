#include <windows.h>
#include <winnt.h>
extern "C" void SIMPLE_SHELLCODE();
extern "C" void UNIVERSAL_SHELLCODE();

int main(int argc, char* argv[]) {
	// Simple Shellcode
	//char cmd[4] = { 'c', 'm', 'd', '\x00' };
	//WinExec(cmd, SW_SHOW);

	// Universal Shellcode
	//HMODULE hModule = GetModuleHandleA("Kernel32.dll"); 
	//void* addr = GetProcAddress(hModule, "WinExec");
	//printf("%p\n", addr);

	//SIMPLE_SHELLCODE();	// This run only when user knows WinExec's address
	UNIVERSAL_SHELLCODE();
	return 0;
}