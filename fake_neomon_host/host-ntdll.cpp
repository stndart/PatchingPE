#define _X86_

#include <iostream>
#include <windows.h>

#pragma comment(lib, "user32.lib")

#include "loadbin.h"

extern "C" __declspec(dllimport) int NIGS_1();

int main() {
  int addr = 0x77BA0000;
  LPVOID ntdll_base = reinterpret_cast<LPVOID>(static_cast<uint32_t>(addr));

  HMODULE ntdllMod = LoadNtdllAt(ntdll_base);
  if (!ntdllMod)
    return 1;

  std::cout << "NTDLL loaded\n";

  HMODULE hDll = NULL;
  DllMainFunc DllMain = NULL;

  // const char neomon_name[] = "NeoMon.dll";
  const char neomon_name[] = "NeoMon_patched.dll";
  if (!prepare_neomon(hDll, DllMain, neomon_name))
    return 1;

  std::cout << neomon_name << " loaded\n";

  return workflow(hDll);
}