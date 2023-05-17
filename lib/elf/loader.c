//
// Copyright 2023 Aman LaChapelle
// Full license at smithy/LICENSE.txt
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "smithy/elf/loader.h"
#include "smithy/stdlib/bitwise.h"
#include "smithy/stdlib/typed_vector.h"

#include "ELF64.h"

#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

/// Interesting idea - given a pointer to the current process, patch the ELF's
/// debuginfo (if it has any) into the current (runner) process, and replace it
/// on scope exit.

sm_runnable_elf load(sm_file *elf) {
  // Map the file into memory.
  sm_buffer buf = elf->map(elf, 0);

  // Invalid runnable elf.
  sm_runnable_elf out = {.entry = NULL};

  // Load the ELF from the buffer, pull out the entry point, and run it.
  const Elf64_Ehdr *header = (const Elf64_Ehdr *)sm_buffer_begin(buf);
  uint16_t prog_hdr_size = header->e_phentsize;
  uint16_t num_prog_hdrs = header->e_phnum;

  size_t page_size = getpagesize();

  // Get the image base address.
  size_t base_address = SIZE_MAX;
  size_t mapping_size = 0;
  for (uint16_t i = 0; i < num_prog_hdrs; ++i) {
    const Elf64_Phdr *prog_hdr =
        (const Elf64_Phdr *)(sm_buffer_begin(buf) + header->e_phoff +
                             (i * prog_hdr_size));

    if (prog_hdr->p_type & PT_LOAD && prog_hdr->p_memsz > 0) {
      if (prog_hdr->p_vaddr < base_address)
        base_address = prog_hdr->p_vaddr;

      mapping_size +=
          ((prog_hdr->p_memsz + prog_hdr->p_align - 1) / prog_hdr->p_align) *
          prog_hdr->p_align;
    }
  }

  // Truncate to the nearest page.
  base_address &= ~(page_size - 1);
  SM_DEBUG("Base address for ELF image: 0x%llx\n", base_address);

  void *image = mmap((void *)base_address, mapping_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (image == MAP_FAILED) {
    SM_ERROR("Mapping the image failed with %s\n", strerror(errno));
    return out;
  }
  // Memset the entire mapping to 0, we'll copy the data in presently.
  memset(image, 0, mapping_size);

  for (uint16_t i = 0; i < num_prog_hdrs; ++i) {
    const Elf64_Phdr *prog_hdr =
        (const Elf64_Phdr *)(sm_buffer_begin(buf) + header->e_phoff +
                             (i * prog_hdr_size));

    // Handle a LOAD segment.
    if (SM_CHECK_MASK(prog_hdr->p_type, PT_LOAD)) {
      // Don't do anything for the GNU_STACK. It's a legacy program header.
      if (SM_CHECK_MASK(prog_hdr->p_type, PT_GNU_STACK))
        continue;

      SM_DEBUG(
          "Handling PT_LOAD segment (Offset=0x%llx, VirtualAddr=0x%llx, "
          "MemorySize=0x%llx, FileSize=0x%llx, Flags=0x%llx, Align=0x%llx)\n",
          prog_hdr->p_offset, prog_hdr->p_vaddr, prog_hdr->p_memsz,
          prog_hdr->p_filesz, prog_hdr->p_flags, prog_hdr->p_align);

      // TODO: This would be better done as an mmap of the data in the file
      //   directly. Have to think more about this
      // Copy the data for the program into place.
      memcpy((void *)prog_hdr->p_vaddr,
             sm_buffer_begin(buf) + prog_hdr->p_offset, prog_hdr->p_filesz);

      // The program header permissions are exactly the mmap permissions with R
      // and X swapped. Reset the permissions here.
      unsigned mmap_prot = ((prog_hdr->p_flags & 0x1) << 2) |
                           (prog_hdr->p_flags & 0x2) |
                           ((prog_hdr->p_flags & 0x4) >> 2);
      // Truncate to the nearest page boundary. The alignment requirements
      // should handle this.
      void *page = (void *)(prog_hdr->p_vaddr & ~(page_size - 1));
      if (mprotect(page, prog_hdr->p_memsz, (int)mmap_prot) == -1) {
        SM_ERROR("Setting page permissions for 0x%llx failed with %s\n", page,
                 strerror(errno));
        return out;
      }

      // Push the mapped segment into the typed vector.
      //      sm_typed_vector_push(&loaded_segments, mem);
      continue;
    }

    // TODO: Handle an INTERP segment.
  }

  // Truncate the base address to the page size.

  base_address &= ~page_size;

  // Set the entry point, we've successfully loaded everything.
  out.entry = (int (*)(int, char **))header->e_entry;

  return out;
}
