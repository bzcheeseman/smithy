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

#include "smithy/stdlib/twine.h"

sm_twine *sm_twine_append(sm_twine *t, sm_twine *elt) {
  sm_ilist_push_back((sm_ilist *)t, (sm_ilist *)elt);
  return elt;
}

void sm_twine_render(const sm_twine t, sm_buffer *dest) {
  const sm_twine *iter;
  sm_ilist_for_each(&t, iter) {
    sm_buffer_insert(dest, sm_buffer_end(*dest), sm_buffer_begin(iter->data),
                     sm_buffer_end(iter->data));
  }
}
