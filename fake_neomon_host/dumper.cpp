// dump_dll32_scylla_like_fixed2.cpp
// 32-bit-only memory-to-file PE dumper with last-nonzero scan (Scylla-like).
// Loads "NeoMon.dll" and writes "NeoMon_dump.dll".
// Build for x86 (match DLL bitness).

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>

static SIZE_T align_up(SIZE_T val, SIZE_T align) {
  if (align == 0)
    return val;
  return ((val + align - 1) / align) * align;
}

static std::string sect_name(const IMAGE_SECTION_HEADER &s) {
  char buf[9] = {0};
  memcpy(buf, s.Name, 8);
  return std::string(buf);
}

int main() {
  const char *dllName = "NeoMon.dll";
  const char *outName = "NeoMon_dump.dll";

  HMODULE hMod = LoadLibraryA(dllName);
  if (!hMod) {
    std::cerr << "LoadLibraryA failed for " << dllName << " (error "
              << GetLastError() << ")\n";
    return 1;
  }
  BYTE *base = reinterpret_cast<BYTE *>(hMod);
  if (!base) {
    std::cerr << "Module base is null\n";
    return 1;
  }

  PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    std::cerr << "Bad DOS signature\n";
    return 1;
  }

  PIMAGE_NT_HEADERS32 nt =
      reinterpret_cast<PIMAGE_NT_HEADERS32>(base + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    std::cerr << "Bad NT signature\n";
    return 1;
  }
  if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
    std::cerr << "Not a 32-bit PE (OptionalHeader.Magic = 0x" << std::hex
              << nt->OptionalHeader.Magic << ")\n";
    return 1;
  }

  DWORD numSections = nt->FileHeader.NumberOfSections;
  DWORD sizeOfHeaders = nt->OptionalHeader.SizeOfHeaders;
  SIZE_T sizeOfImage = nt->OptionalHeader.SizeOfImage;
  DWORD fileAlign = nt->OptionalHeader.FileAlignment;
  if (fileAlign == 0)
    fileAlign = 0x200;

  std::cout << "32-bit PE detected. Sections: " << numSections
            << " SizeOfHeaders: 0x" << std::hex << sizeOfHeaders
            << " SizeOfImage: 0x" << sizeOfImage << " FileAlignment: 0x"
            << fileAlign << std::dec << "\n";

  // Copy headers (up to reported SizeOfHeaders) into output buffer, aligned to
  // file alignment.
  SIZE_T headersOnDisk = align_up(sizeOfHeaders, fileAlign);
  std::vector<BYTE> out;
  out.resize(headersOnDisk, 0);
  memcpy(out.data(), base, sizeOfHeaders);

  // Memory section table pointer (source)
  PIMAGE_SECTION_HEADER mem_sect = IMAGE_FIRST_SECTION(nt);

  // Helper: next section virtual address (or SizeOfImage if last)
  auto next_vaddr = [&](DWORD idx) -> DWORD {
    if (idx + 1 < numSections)
      return mem_sect[idx + 1].VirtualAddress;
    return static_cast<DWORD>(sizeOfImage ? sizeOfImage
                                          : (mem_sect[idx].VirtualAddress +
                                             mem_sect[idx].Misc.VirtualSize));
  };

  // Start allocating raw data after headers
  SIZE_T currentRaw = headersOnDisk;

  for (DWORD i = 0; i < numSections; ++i) {
    DWORD vaddr = mem_sect[i].VirtualAddress;
    DWORD vsize = mem_sect[i].Misc.VirtualSize;
    DWORD rawsz_mem = mem_sect[i].SizeOfRawData;
    DWORD n_vaddr = next_vaddr(i);

    // Align original raw size (on-disk) if present
    SIZE_T origRawAligned =
        rawsz_mem ? align_up(static_cast<SIZE_T>(rawsz_mem), fileAlign) : 0;

    // Candidate: virtual size (aligned)
    SIZE_T virtAligned =
        vsize ? align_up(static_cast<SIZE_T>(vsize), fileAlign) : 0;

    // Candidate: bytes available until next section (virtual)
    SIZE_T bytesUntilNext = 0;
    if (n_vaddr > vaddr)
      bytesUntilNext = static_cast<SIZE_T>(n_vaddr - vaddr);
    SIZE_T untilNextAligned =
        bytesUntilNext ? align_up(bytesUntilNext, fileAlign) : 0;

    // preferGrow (upper cap): min(virtAligned, untilNextAligned) if both
    // present
    SIZE_T preferGrow = 0;
    if (virtAligned && untilNextAligned)
      preferGrow = min(virtAligned, untilNextAligned);
    else if (virtAligned)
      preferGrow = virtAligned;
    else if (untilNextAligned)
      preferGrow = untilNextAligned;

    // === New: scan section memory to find last non-zero byte ===
    SIZE_T scanMax = 0;
    if (vaddr < sizeOfImage) {
      scanMax = sizeOfImage - vaddr;
      if (vsize)
        scanMax = min(scanMax, static_cast<SIZE_T>(vsize));
      else if (bytesUntilNext)
        scanMax = min(scanMax, bytesUntilNext);
    }
    BYTE *scanBase = (scanMax ? (base + vaddr) : nullptr);
    SIZE_T lastNonZero = 0;
    if (scanBase) {
      // find last non-zero byte in [0..scanMax)
      for (SIZE_T off = scanMax; off > 0; --off) {
        if (scanBase[off - 1] != 0) {
          lastNonZero = off;
          break;
        }
      }
    }
    SIZE_T lastNonZeroAligned =
        lastNonZero ? align_up(lastNonZero, fileAlign) : 0;

    // Compute chosenRaw combining origRawAligned, lastNonZeroAligned and
    // preferGrow caps
    SIZE_T chosenRaw = 0;
    if (origRawAligned) {
      // ensure at least original raw; if lastNonZero requires growth, apply it
      chosenRaw = origRawAligned;
      if (lastNonZeroAligned && lastNonZeroAligned > chosenRaw)
        chosenRaw = lastNonZeroAligned;
    } else {
      // no orig raw: use lastNonZeroAligned if present, otherwise fall back to
      // preferGrow or fileAlign
      if (lastNonZeroAligned)
        chosenRaw = lastNonZeroAligned;
      else if (preferGrow)
        chosenRaw = preferGrow;
      else
        chosenRaw = fileAlign;
    }
    if (i == 0) {
      chosenRaw = 0x1D200;
    }

    // finally cap growth by preferGrow if preferGrow is available (don't grow
    // into next section)
    if (preferGrow && chosenRaw > preferGrow)
      chosenRaw = preferGrow;

    if (chosenRaw == 0)
      chosenRaw = fileAlign;

    // Ensure currentRaw is aligned to FileAlignment
    if (currentRaw % fileAlign)
      currentRaw = align_up(currentRaw, fileAlign);

    // Calculate needed final size (headers + already-placed + this section)
    SIZE_T need = currentRaw + chosenRaw;

    // Resize OUT buffer *before* taking pointers into it
    if (out.size() < need)
      out.resize(need, 0);

    // Derive header pointers from out and update them
    PIMAGE_DOS_HEADER out_dos = reinterpret_cast<PIMAGE_DOS_HEADER>(out.data());
    PIMAGE_NT_HEADERS32 out_nt =
        reinterpret_cast<PIMAGE_NT_HEADERS32>(out.data() + out_dos->e_lfanew);
    PIMAGE_SECTION_HEADER out_sect = IMAGE_FIRST_SECTION(out_nt);

    out_sect[i].PointerToRawData = static_cast<DWORD>(currentRaw);
    out_sect[i].SizeOfRawData = static_cast<DWORD>(chosenRaw);
    if (i == 0) {
      out_sect[i].Characteristics = 0xE0000020;
    }

    // Copy from memory into the allocated raw area (limit by SizeOfImage)
    SIZE_T avail = 0;
    if (vaddr < sizeOfImage)
      avail = sizeOfImage - vaddr;
    SIZE_T toCopy = 0;
    if (vsize)
      toCopy = std::min<SIZE_T>(vsize, avail);
    else if (rawsz_mem)
      toCopy = std::min<SIZE_T>(rawsz_mem, avail);
    if (toCopy > chosenRaw)
      toCopy = chosenRaw;

    if (toCopy > 0 && vaddr < sizeOfImage) {
      memcpy(out.data() + currentRaw, base + vaddr, toCopy);
    }

    std::cout << std::hex << "Section " << std::setw(8)
              << sect_name(mem_sect[i]) << " : virt@0x" << vaddr << " vsize=0x"
              << vsize << " raw_mem=0x" << rawsz_mem << " lastNonZero=0x"
              << lastNonZero << " -> chosenRaw=0x" << chosenRaw << " raw@0x"
              << out_sect[i].PointerToRawData << std::dec << "\n";

    // advance currentRaw
    currentRaw += chosenRaw;
  }

  // Shrink to used size
  out.resize(currentRaw);

  // Write file
  std::ofstream ofs(outName, std::ios::binary | std::ios::trunc);
  if (!ofs) {
    std::cerr << "Failed to open output file for writing: " << outName << "\n";
    FreeLibrary(hMod);
    return 1;
  }
  ofs.write(reinterpret_cast<const char *>(out.data()),
            static_cast<std::streamsize>(out.size()));
  ofs.close();

  std::cout << "Wrote dump to " << outName << " (" << out.size() << " bytes)\n";

  FreeLibrary(hMod);
  return 0;
}
