#include <Windows.h>

#include <DbgHelp.h>
#include <cstdio>

#pragma comment(lib, "Dbghelp.lib")

int main() {
  HANDLE hProcess = GetCurrentProcess();
  SymInitialize(hProcess, NULL, TRUE);
  DWORD64 addr =
      (DWORD64)GetProcAddress(GetModuleHandle("kernel32.dll"), "HeapAlloc");
  SYMBOL_INFO sym = {sizeof(SYMBOL_INFO), 0};
  sym.MaxNameLen = MAX_SYM_NAME;
  SymFromAddr(hProcess, addr, 0, &sym);
  printf("Ptr: %p\n", addr);
  printf("Function: %s\n", sym.Name);
}
