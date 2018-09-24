/*############################################################################
# Copyright 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
############################################################################*/
/// A SHA-384 implementation.
/*! \file */

#include <stdint.h>

#include "epid/member/tiny/math/sha384.h"
#include "epid/member/tiny/stdlib/tiny_stdlib.h"

static const uint64_t kIv384[SHA384_DIGEST_WORDS] = {
    0xcbbb9d5dc1059ed8ULL, 0x629a292a367cd507ULL, 0x9159015a3070dd17ULL,
    0x152fecd8f70e5939ULL, 0x67332667ffc00b31ULL, 0x8eb44a8768581511ULL,
    0xdb0c2e0d64f98fa7ULL, 0x47b5481dbefa4fa4ULL};
void tinysha384_init(sha384_state* s) {
  tinysha512_base_init(&s->state, kIv384);
}

void tinysha384_update(sha384_state* s, void const* data, size_t data_length) {
  // The function is defined in the exact same manner as SHA-512
  tinysha512_base_update(&s->state, data, data_length);
}

void tinysha384_final(unsigned char* digest, sha384_state* s) {
  // The function is defined in the exact same manner as SHA-512
  tinysha512_base_final(digest, SHA384_DIGEST_SIZE, &s->state);
}
