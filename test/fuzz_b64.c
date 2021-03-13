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

#include "smithy/stdlib/b64.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {

  const sm_buffer in = {
      .data = Data,
      .length = Size,
      .capacity = Size,
  };

  SM_AUTO(sm_buffer) encoded = sm_empty_buffer;
  SM_AUTO(sm_buffer) decoded = sm_empty_buffer;
  // Try all the variants
  for (int e = SM_B64_STANDARD_ENCODING; e < SM_B64_ENCODING_END; ++e) {
    (void)sm_b64_encode(e, in, &encoded);
    (void)sm_b64_decode(e, encoded, &decoded);
  }

  return 0; // Non-zero return values are reserved for future use.
}
