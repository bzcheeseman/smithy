//
// Copyright 2022 Aman LaChapelle
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

#include "smithy/stdlib/filesystem.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static bool sm_fs_write(const sm_file *file, const sm_buffer buf) {
  FILE *fptr = (FILE *)file->handle;

  size_t bytes_written = fwrite(sm_buffer_begin(buf), 1, buf.length, fptr);
  if (bytes_written < buf.length && ferror(fptr)) {
    SM_ERROR("Unable to write file: %s\n", strerror(errno));
    return false;
  }

  return true;
}

static bool sm_fs_read(const sm_file *file, sm_buffer *buf) {
  FILE *fptr = (FILE *)file->handle;
  if (fseek(fptr, 0, SEEK_END) != 0) {
    SM_ERROR("Unable to seek file: %s\n", strerror(errno));
    fclose(fptr);
    return false;
  }

  size_t fsize = ftell(fptr);
  rewind(fptr);

  // Make sure there's enough space in the buffer
  sm_buffer_reserve(buf, buf->length + fsize);

  // Read into the end of the buffer
  size_t bytes_read = fread(sm_buffer_end(*buf), 1, fsize, fptr);
  if (bytes_read < fsize && feof(fptr)) {
    SM_ERROR("Unable to read file: EOF\n", strerror(errno));
    return false;
  } else if (bytes_read < fsize && ferror(fptr)) {
    SM_ERROR("Unable to read file: %s\n", strerror(errno));
    return false;
  } else if (bytes_read < fsize) {
    SM_ERROR("Unable to read file: Unknown error\n");
    return false;
  }

  // Increment the length
  buf->length += bytes_read;

  return true;
}

size_t sm_fs_size(const sm_file *f) {
  int fd = fileno((FILE *)f->handle);

  // Read the file size (should be the same as size)
  struct stat st;
  bool exists = fstat(fd, &st) == 0;
  SM_ASSERT(exists && "File should already be open at this point?");
  return st.st_size;
}

sm_buffer sm_fs_map(const sm_file *f, size_t size) {
  int fd = fileno((FILE *)f->handle);
  int file_flags = fcntl(fd, F_GETFL);

  // If the size is specified, then ftruncate the file
  if (size > 0) {
    int rc = ftruncate(fd, size);
    if (rc != 0) {
      SM_ERROR("Failed to update file size: %s\n", strerror(errno));
      return sm_empty_buffer;
    }
  }

  // Read the file size (should be the same as size)
  struct stat st;
  bool exists = fstat(fd, &st) == 0;
  SM_ASSERT(exists && "File should already be open at this point?");
  SM_ASSERT(
      size == 0 ||
      st.st_size == size &&
          "If size was specified the file should match that size already?");
  size = st.st_size;
  if (size == 0) {
    SM_DEBUG("File size was 0 and no size was specified, returning an empty "
             "buffer\n");
    return sm_empty_buffer;
  }

  // Get the flags for mmap - if any of the flags are set (RDWR or WRONLY)
  int mmap_flags = PROT_READ;
  if (file_flags & O_ACCMODE) {
    mmap_flags |= PROT_WRITE;
  }

  if (file_flags == O_WRONLY) {
    // preserve write only
    mmap_flags = PROT_WRITE;
  }

  if (mmap_flags == 0) {
    SM_INFO("Mapping with prot_none, returning sm_empty_buffer\n");
    return sm_empty_buffer;
  }

  void *mapped = mmap(NULL, size, mmap_flags, MAP_SHARED, fd, 0);
  if (mapped == MAP_FAILED) {
    SM_ERROR("mmap failed: %s\n", strerror(errno));
    return sm_empty_buffer;
  }

  return sm_buffer_alias_mmap(mapped, size);
}

void sm_fs_unmap(const sm_buffer buf) {
  munmap(sm_buffer_begin(buf), buf.length);
}

sm_file *sm_open(const char *path, const char *mode) {
  FILE *f = fopen(path, mode);
  if (f == NULL) {
    SM_ERROR("Unable to open file %s with mode %s: %s\n", path, mode,
             strerror(errno));
    return NULL;
  }

  sm_file *out = sm_malloc(sizeof(sm_file));
  out->handle = (uint64_t)f;
  // Set up symbol table
  out->write = &sm_fs_write;
  out->read = &sm_fs_read;
  out->size = &sm_fs_size;
  out->map = &sm_fs_map;
  out->unmap = &sm_fs_unmap;
  return out;
}

void sm_close(sm_file *f) {
  if (!f || !f->handle) {
    return;
  }
  FILE *fptr = (FILE *)f->handle;
  fflush(fptr);
  fclose(fptr);
  f->handle = 0;
  sm_free(f);
}

sm_file *sm_stderr() {
  sm_file *out = sm_malloc(sizeof(sm_file));
  out->handle = (uint64_t)stderr;
  // Set up symbol table
  out->write = &sm_fs_write;
  out->read = &sm_fs_read;
  out->size = &sm_fs_size;
  out->map = &sm_fs_map;
  out->unmap = &sm_fs_unmap;
  return out;
}

sm_file *sm_stdout() {
  sm_file *out = sm_malloc(sizeof(sm_file));
  out->handle = (uint64_t)stdout;
  // Set up symbol table
  out->write = &sm_fs_write;
  out->read = &sm_fs_read;
  out->size = &sm_fs_size;
  out->map = &sm_fs_map;
  out->unmap = &sm_fs_unmap;
  return out;
}
