#pragma once

#include <iostream>

#include <windows.h>

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

typedef BOOL(WINAPI *DllMainFunc)(HINSTANCE, DWORD, LPVOID);

int prepare_neomon(HMODULE &hDll, DllMainFunc &DllMain,
                   const char *neomon_name) {
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

  HMODULE h;
  h = LoadLibraryA("user32.dll");

  hDll = LoadLibrary(neomon_name);

  if (!hDll) {
    std::cout << "Failed to load DLL" << std::endl;
    return 1;
  }

  DllMain = (DllMainFunc)GetProcAddress(hDll, "DllMain");
  if (DllMain) {
    return 0;
  } else {
    std::cout << "Failed to locate DllMain\n";
    return 1;
  }
}

HMODULE LoadNtdllAt(LPVOID DesiredBase) {
  // If it's already loaded, return the module handle.
  HMODULE hExisting = GetModuleHandleW(L"ntdll.dll");
  if (hExisting) {
    std::cout << "Ntdll is already loaded at "
              << static_cast<void *>(hExisting);
    if (hExisting == reinterpret_cast<HMODULE>(DesiredBase))
      std::cout << ", which is fine\n";
    else
      std::cout << ", which is bad\n";
    return hExisting;
  }

  // Build full path to system ntdll.dll
  std::wstring dllPath = L"C:/Windows/SysWOW64/ntdll.dll";

  // Open file for read-only access
  HANDLE hFile =
      CreateFileW(dllPath.c_str(), GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    std::cout << "Could not load ntdll.dll\n";
    return NULL;
  }

  // Create a file mapping with SEC_IMAGE so the OS treats it like an executable
  // image. Use pointer-sized types; protection PAGE_READONLY | SEC_IMAGE is
  // appropriate for image mapping.
  HANDLE hMapping =
      CreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
  if (hMapping == NULL) {
    std::cout << "Could not map ntdll.dll\n";
    CloseHandle(hFile);
    return NULL;
  }

  // Try to map the image at the requested base (DesiredBase may be NULL to let
  // system choose)
  LPVOID mapped =
      MapViewOfFileEx(hMapping, FILE_MAP_READ, 0, 0, 0, DesiredBase);
  if (mapped == NULL) {
    std::cout << "Could not map loaded ntdll.dll to "
              << static_cast<void *>(DesiredBase) << "\n";
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return NULL;
  }

  // Mapping succeeded — we can close the file mapping handle and file handle;
  // the view remains mapped into the process until UnmapViewOfFile.
  CloseHandle(hMapping);
  CloseHandle(hFile);

  std::cout << "Successfully mapped ntdll.dll to "
            << static_cast<void *>(DesiredBase) << "\n";

  return reinterpret_cast<HMODULE>(mapped);
}
