#define _X86_
#include <windows.h>

#include "loadbin.h"

// Reserve space for Themida's special region
#pragma comment(linker, "/BASE:0x400000")
#pragma comment(linker, "/RESERVE:0x02140000-0x02180000")

int main() {
  HMODULE hDll = NULL;
  DllMainFunc DllMain = NULL;
  if (!prepare_neomon(hDll, DllMain)) {
    return 1;
  } else {
    return workflow(hDll);
    return 0;
  }
}