#include <iostream>

char *some_ptr;

int main() {
  std::cout << "Some_ptr is 0x" << std::hex << (int)some_ptr << "\n";
  std::cout << "Some_ptr addr is 0x" << std::hex << (int)(&some_ptr) << "\n";
  std::cin.get();
  return 0;
}