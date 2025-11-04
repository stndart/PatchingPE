#define _X86_

#include <iostream>
#include <windows.h>

// Forward declaration of the function from DLL
extern "C" __declspec(dllimport) int NIGS_1();
extern "C" __declspec(dllimport) int NIGS_2(uint32_t fp, int a1,
                                            HANDLE hThread);

void patch_neomon(bool patch_flag) {
  HMODULE h;
  h = LoadLibraryA("user32.dll");
  std::cout << "Loaded user32.dll at " << std::hex << h << std::endl;

  HMODULE hnm;
  hnm = GetModuleHandle("NeoMon.dll");
  if (!hnm) {
    std::cout << "Failed to acquire neomon handle\n";
    return;
  }
  std::cout << "Found neomon.dll at " << std::hex << hnm << std::endl;

  FARPROC findwindowa = GetProcAddress(h, "FindWindowA");
  if (!findwindowa) {
    std::cout << "Failed to find FindWindowA in user32.dll\n";
    return;
  }
  std::cout << "Found FindWindowA at " << std::hex
            << reinterpret_cast<void *>(findwindowa) << std::endl;

  DWORD *old_fwa_ptr =
      reinterpret_cast<DWORD *>(reinterpret_cast<BYTE *>(hnm) + 0x27571);
  DWORD old_fwa = *old_fwa_ptr;

  DWORD proc_dec_key =
      reinterpret_cast<DWORD *>(reinterpret_cast<BYTE *>(hnm) + 0x1aebe7)[0];
  std::cout << "Proc addr decryption key: " << std::hex << proc_dec_key << "\n";

  std::cout << "Bytes at old findwindowa address[0x" << std::hex
            << (int)old_fwa_ptr << "]: " << std::hex << old_fwa << "\n";
  DWORD dec_fwa = old_fwa ^ proc_dec_key;
  std::cout << "Decrypted: " << std::hex << dec_fwa << "\n";

  DWORD *old_user32_ptr =
      reinterpret_cast<DWORD *>(reinterpret_cast<BYTE *>(hnm) + 0x1e1f58);
  DWORD old_user32 = *old_user32_ptr;

  DWORD mod_dec_key = 0x2c896e24;
  std::cout << "Bytes at old user32 address[0x" << std::hex
            << (int)old_user32_ptr << "]: " << std::hex << old_user32 << "\n";
  DWORD dec_user32 = old_user32 + mod_dec_key;
  std::cout << "Decrypted: " << std::hex << dec_user32 << "\n";

  DWORD n1 = ((DWORD)h) - mod_dec_key;
  std::cout << "Replacing with actual addresses.\nUser32.dll:\n"
            << std::hex << old_user32 << " -> " << std::hex << n1 << "\n";

  DWORD n2 = ((DWORD)findwindowa) ^ proc_dec_key;
  std::cout << "FindWindowA:\n"
            << std::hex << old_fwa << " -> " << std::hex << n2 << "\n";

  if (patch_flag) {
    old_user32_ptr[0] = n1;
    old_fwa_ptr[0] = n2;
    std::cout << "Done\n";
  } else {
    std::cout << "Skipped patch\n";
  }
}

int main() {
  std::cout << "DLL will load automatically due to implicit linking..."
            << std::endl;
  std::cout << "Set breakpoint here - DLL should be unpacked by now!"
            << std::endl;

  patch_neomon(false);

  std::cout << "Press Enter to call functions..." << std::endl;
  std::cin.get();

  int a = NIGS_1();
  std::cout << "Function NIGS_1 called successfully: " << std::hex << a
            << std::endl;
  std::cout << "Press Enter to run a loop..." << std::endl;
  std::cin.get();

  size_t M = 10;
  for (size_t i = 0; i < M; ++i)
    Sleep(100);

  std::cout << "Loop ended successfully!" << std::endl;
  std::cout << "Press Enter to exit..." << std::endl;
  std::cin.get();

  return 0;
}