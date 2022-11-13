//
// Copyright 2022 Aman LaChapelle
// Full license at keyderiver/LICENSE.txt
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

#include "smithy/cache/cache.h"
#include "smithy/stdlib/filesystem.h"

#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <stdio.h>
#include <sys/stat.h>

static void sm_cache_set_dir(sm_cache *c, const char *path) {
  c->path = sm_calloc(strlen(path) + 1, sizeof(char));
  memcpy(c->path, path, strlen(path));

  // If the directory doesn't exist, create it
  struct stat dir_stat;
  if (stat(c->path, &dir_stat) == 0) {
    // The path (if it exists) should point to a directory NOT a file
    SM_ASSERT(S_ISDIR(dir_stat.st_mode));
    return;
  }

  int status = mkdir(c->path, S_IRWXU);
  if (status < 0) {
    SM_ERROR("Failed to create directory %s: %s\n", c->path, strerror(errno));
    sm_free(c->path);
  }
}

static void sm_cache_set_nodir(sm_cache *c) {
  c->path = sm_malloc(2);
  // No directory is indicated by a single -1 byte, followed by a null
  // temrinator
  *c->path++ = -1;
  *c->path = 0;
}

void sm_cache_init(sm_cache *c, const char *path) {
  sm_hash_table_init(&c->hot);
  if (path != NULL)
    return sm_cache_set_dir(c, path);

  sm_cache_set_nodir(c);
}

void sm_cache_cleanup(sm_cache *c) {
  sm_hash_table_cleanup(&c->hot);
  sm_free(c->path);
}

//===--------------------------===//
// File access helpers
//===--------------------------===//

static sm_buffer make_filename(sm_cache *c, const char *key) {
  const char *dirname = c->path;
  size_t filelen = 1 + strlen(key) + 1;
  if (dirname) {
    filelen += strlen(dirname);
  }
  char *out = (char *)sm_calloc(filelen, sizeof(char));
  int printed = dirname ? snprintf(out, filelen, "%s/%s", dirname, key)
                        : snprintf(out, filelen, "/%s", key);
  if (printed < 0) {
    sm_free(out);
    SM_ERROR("Failed to construct filename: %s\n", strerror(errno));
    return sm_empty_buffer;
  }
  return sm_buffer_alias_str(out);
}

static bool file_exists(const char *filename) {
  struct stat st;
  bool exists = stat(filename, &st) == 0;
  return exists;
}

static void remove_file(const char *filename) { (void)remove(filename); }

#define CACHE_NOPATH(c) ((c)->path[0] == -1 && (c)->path[1] == 0)

void sm_cache_put(sm_cache *c, const char *key, const sm_buffer data) {
  SM_ASSERT(c->path && "No persistent path set");

  // Store the data in the hash table
  sm_hash_table_put(&c->hot, sm_buffer_alias_str(key), data);

  // Check for nopath
  if (CACHE_NOPATH(c)) {
    return;
  }

  const SM_AUTO(sm_buffer) filename = make_filename(c, key);

  // Write the data to the file
  SM_AUTO(sm_file) *f = sm_open(sm_buffer_as_str(filename), "w");
  SM_ASSERT(f != NULL);
  SM_ASSERT(f->write(f, data));
}

bool sm_cache_get(sm_cache *c, const char *key, sm_buffer *out) {
  SM_ASSERT(c->path && "No persistent path set");

  // Grab the data from the inmem cache, if it's there.
  if (sm_hash_table_get(&c->hot, sm_buffer_alias_str(key), out)) {
    return true;
  }

  // Check for nopath
  if (CACHE_NOPATH(c)) {
    return false;
  }

  const SM_AUTO(sm_buffer) filename = make_filename(c, key);

  // If the file does not exist, at this point there's nothing we can do
  if (!file_exists(sm_buffer_as_str(filename))) {
    return false;
  }

  SM_AUTO(sm_file) *f = sm_open(sm_buffer_as_str(filename), "r");
  SM_ASSERT(f != NULL);

  // Copy only the data in the buffer - there might be more in `out`
  SM_AUTO(sm_buffer) filedata = sm_empty_buffer;
  SM_ASSERT(f->read(f, &filedata));

  // Copy the data into the output buffer
  sm_buffer_insert(out, sm_buffer_end(*out), sm_buffer_begin(filedata),
                   sm_buffer_end(filedata));

  // Also copy the data into the inmem cache
  sm_hash_table_put(&c->hot, sm_buffer_alias_str(key), filedata);

  return true;
}

bool sm_cache_exists(sm_cache *c, const char *key) {
  SM_ASSERT(c->path && "No persistent path set");

  if (sm_hash_table_exists(&c->hot, sm_buffer_alias_str(key))) {
    return true;
  }

  // Check for nopath
  if (CACHE_NOPATH(c)) {
    return false;
  }

  const SM_AUTO(sm_buffer) filename = make_filename(c, key);

  // Don't map the file, just see if it exsts
  bool exists = file_exists(sm_buffer_as_str(filename));

  if (!exists) {
    return false;
  }

  // It exists, but it doesn't exist in the hot cache, so pull it in
  SM_AUTO(sm_buffer) tmp = sm_empty_buffer;
  SM_ASSERT(sm_cache_get(c, key, &tmp));

  return true;
}

void sm_cache_remove(sm_cache *c, const char *key) {
  // If it doesn't exist, don't try and remove it
  if (!sm_cache_exists(c, key)) {
    return;
  }

  // Delete it from the hash table
  sm_hash_table_remove(&c->hot, sm_buffer_alias_str(key));

  // Check for nopath
  if (CACHE_NOPATH(c)) {
    return;
  }

  const SM_AUTO(sm_buffer) filename = make_filename(c, key);
  // If it doesn't exist, don't need to do anything
  if (!file_exists(sm_buffer_as_str(filename))) {
    return;
  }

  // If the file exists, remove it (this will do nothing if the file doesn't
  // exist)
  SM_AUTO(sm_file) *f = sm_open(sm_buffer_as_str(filename), "w+");
  sm_buffer filedata = f->map(f, 0);
  if (!sm_buffer_empty(filedata)) {
    // Clean out the file (set the data to zeros)
    sm_buffer_clear(&filedata);
    // Unmap the file
    f->unmap(filedata);
  }
  // And remove the file itself
  remove_file(sm_buffer_as_str(filename));
}

static int unlink_cb(const char *fpath, const struct stat *sb, int typeflag,
                     struct FTW *ftwbuf) {
  (void)sb;
  (void)typeflag;
  (void)ftwbuf;

  int fd = open(fpath, O_WRONLY);
  if (fd < 0) {
    // Don't need to open a file that doesn't exist
    return 0;
  }

  SM_AUTO(sm_file) *f = sm_open(fpath, "w+");
  sm_buffer filedata = f->map(f, 0);
  sm_buffer_clear(&filedata);
  f->unmap(filedata);

  // Remove the file
  int rv = remove(fpath);
  if (rv) {
    SM_ERROR("Unable to remove file: %s\n", fpath);
  }

  return rv;
}

void sm_cache_clear(sm_cache *c) {
  sm_hash_table_clear(&c->hot);

  // Check for nopath
  if (CACHE_NOPATH(c)) {
    return;
  }

  // Clean out the file cache by removing all the files in the dir
  nftw(c->path, &unlink_cb, 64, FTW_DEPTH | FTW_PHYS);

  // Free the path and set it to NULL
  sm_free(c->path);
  c->path = NULL;
}
