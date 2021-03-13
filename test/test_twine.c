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
#include <printf.h>

void simple() {
  sm_twine twine = sm_twine_alias_str("Hello!");

  SM_AUTO(sm_buffer) out = sm_empty_buffer;
  sm_twine_render(twine, &out);
  SM_ASSERT(sm_buffer_equal(out, sm_buffer_alias_str("Hello!")));
}

void concat_strings() {
  sm_twine hello = sm_twine_alias_str("Hello");
  sm_twine space = sm_twine_alias_str(" ");
  sm_twine_append(&hello, &space);
  sm_twine world = sm_twine_alias_str("world");
  sm_twine *wrld = sm_twine_append(&space, &world);
  sm_twine excl = sm_twine_alias_str("!");
  sm_twine_append(wrld, &excl);

  SM_AUTO(sm_buffer) out = sm_empty_buffer;
  sm_twine_render(hello, &out);
  SM_ASSERT(sm_buffer_equal(out, sm_buffer_alias_str("Hello world!")));
}

int main() {
  simple();
  concat_strings();
}
