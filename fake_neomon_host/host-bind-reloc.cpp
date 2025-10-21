#define _X86_
#include <iostream>
#include <windows.h>

// Reserve space for Themida's special region
#pragma comment(linker, "/BASE:0x400000")
#pragma comment(linker, "/RESERVE:0x02140000-0x02180000")

typedef BOOL(WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);

// Forward declaration of the function from DLL
// extern "C" __declspec(dllimport) int NIGS_1();
// extern "C" __declspec(dllimport) int NIGS_2();
// extern "C" __declspec(dllimport) int NIGS_3();
// extern "C" __declspec(dllimport) int NIGS_4();
// extern "C" __declspec(dllimport) int NIGS_5();
// extern "C" __declspec(dllimport) int NIGS_6();
// extern "C" __declspec(dllimport) int NIGS_7();

int workflow(HINSTANCE);

int loadbin(const char *fn, LPVOID base_addr) {
  // Manually map the Themida region from a separate file
  HANDLE hFile = CreateFile(fn, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

  if (hFile != INVALID_HANDLE_VALUE) {
    LPVOID themidaRegion = VirtualAlloc(
        base_addr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    std::cout << "Allocation successfull at " << std::hex
              << (long long)themidaRegion << std::endl;
    DWORD bytesRead;
    ReadFile(hFile, themidaRegion, 0x1000, &bytesRead, NULL);
    CloseHandle(hFile);

    return 0;
  } else {
    std::cout << "Failed to load " << fn << std::endl;
    return 1;
  }
}

int main() {
  if (loadbin("neomon213.bin", (LPVOID)0x2130000))
    return 1;
  if (loadbin("neomon214.bin", (LPVOID)0x2140000))
    return 1;
  if (loadbin("neomon215.bin", (LPVOID)0x2150000))
    return 1;
  if (loadbin("neomon216.bin", (LPVOID)0x2160000))
    return 1;
  if (loadbin("neomon217.bin", (LPVOID)0x2170000))
    return 1;

  HMODULE hDll = LoadLibrary("NeoMon.dll");

  if (!hDll) {
    std::cout << "Failed to load DLL" << std::endl;
    return 1;
  }

  // Now call the DLL entry point
  DllMainFunc DllMain = (DllMainFunc)GetProcAddress(hDll, "DllMain");
  if (DllMain) {
    DllMain((HINSTANCE)hDll, DLL_PROCESS_ATTACH, NULL);
  } else {
    std::cout << "Failed to locate DllMain\n";
    // return 0;
  }
  return workflow(hDll);
}

typedef int (*fs)();

int workflow(HINSTANCE hDll) {
  std::cout << "DLL will load automatically due to implicit linking..."
            << std::endl;
  std::cout << "Set breakpoint here - DLL should be unpacked by now!"
            << std::endl;

  std::cout << "Press Enter to call functions..." << std::endl;
  std::cin.get();

  fs NIGS_1 = (fs)GetProcAddress(hDll, "NIGS_1");
  int a = NIGS_1();
  std::cout << "Function NIGS_1" << " called successfully: " << std::hex << a
            << std::endl;

  std::cout << "Press Enter to run a loop..." << std::endl;
  std::cin.get();

  size_t M = 10;
  for (size_t i = 0; i < M; ++i)
    Sleep(1000);

  std::cout << "Loop ended successfully!" << std::endl;
  std::cout << "Press Enter to exit..." << std::endl;
  std::cin.get();

  return 0;
}