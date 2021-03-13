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

#include "smithy/stdlib/assert.h"
#include "smithy/stdlib/linked_list.h"

typedef struct {
  sm_ilist list_;
  size_t data;
} foo;

void iterate() {
  foo f[3];
  for (size_t i = 0; i < 3; ++i) {
    f[i].list_ = sm_empty_ilist;
    f[i].data = i;
  }

  foo *list = &f[1];

  // Ensure these work as expected - push one onto the front and one onto the
  // back. f[0] now holds the head of the list
  sm_ilist_push_front((sm_ilist *)list, (sm_ilist *)&f[0]);
  list = &f[0];
  sm_ilist_push_back((sm_ilist *)list, (sm_ilist *)&f[2]);

  SM_ASSERT(sm_ilist_length((sm_ilist *)list) == 3);

  size_t i = 0;
  foo *iter;
  sm_ilist_for_each(list, iter) { SM_ASSERT(iter->data == i++); }
}

void ownership() {
  foo *f[3];
  for (size_t i = 0; i < 3; ++i) {
    f[i] = sm_malloc(sizeof(foo));
    f[i]->list_ = sm_empty_ilist;
    f[i]->data = i;
  }

  // Take ownership of the node
  foo *list = (foo *)sm_ilist_take((sm_ilist *)f[1]);

  // Ensure these work as expected - push one onto the front and one onto the
  // back. f[0] now holds the head of the list
  sm_ilist_take_front((sm_ilist *)list, (sm_ilist *)f[0]);
  list = f[0];
  sm_ilist_take_back((sm_ilist *)list, (sm_ilist *)f[2]);

  SM_ASSERT(sm_ilist_length((sm_ilist *)list) == 3);

  size_t i = 0;
  foo *iter;
  sm_ilist_for_each(list, iter) { SM_ASSERT(iter->data == i++); }

  sm_ilist_free((sm_ilist *)list, NULL);
}

typedef struct {
  sm_ilist list_;
  size_t *data;
} bar;

void free_bar(void *b) {
  bar *obj = b;
  sm_free(obj->data);
}

void free_callback() {
  bar *f[3];
  for (size_t i = 0; i < 3; ++i) {
    f[i] = sm_malloc(sizeof(foo));
    f[i]->list_ = sm_empty_ilist;
    f[i]->data = (size_t *)sm_malloc(sizeof(size_t));
    *f[i]->data = i;
  }

  // Take ownership of the node
  bar *list = (bar *)sm_ilist_take((sm_ilist *)f[1]);

  // Ensure these work as expected - push one onto the front and one onto the
  // back. f[0] now holds the head of the list
  sm_ilist_take_front((sm_ilist *)list, (sm_ilist *)f[0]);
  list = f[0];
  sm_ilist_take_back((sm_ilist *)list, (sm_ilist *)f[2]);

  SM_ASSERT(sm_ilist_length((sm_ilist *)list) == 3);

  size_t i = 0;
  bar *iter;
  sm_ilist_for_each(list, iter) { SM_ASSERT(*iter->data == i++); }

  sm_ilist_free((sm_ilist *)list, &free_bar);
}

int main() {
  iterate();
  ownership();
  free_callback();
}
