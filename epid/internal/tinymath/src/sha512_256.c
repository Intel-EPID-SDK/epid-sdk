/*############################################################################
# Copyright 2018-2020 Intel Corporation
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
/// A SHA-512/256 implementation.
/*! \file */

#include <stdint.h>

#include "tinymath/sha512_256.h"
#include "tinystdlib/tiny_stdlib.h"

static const uint64_t kIv512_256[SHA512_256_DIGEST_WORDS] = {
    0x22312194fc2bf72cULL, 0x9f555fa3c84c64c2ULL, 0x2393b86b6f53b151ULL,
    0x963877195940eabdULL, 0x96283ee2a88effe3ULL, 0xbe5e1e2553863992ULL,
    0x2b0199fc2c85b8aaULL, 0x0eb72ddc81c52ca2ULL};

void tinysha512_256_init(sha512_256_state* s) {
  tinysha512_base_init(&s->state, kIv512_256);
}

void tinysha512_256_update(sha512_256_state* s, void const* data,
                           size_t data_length) {
  tinysha512_base_update(&s->state, data, data_length);
}

void tinysha512_256_final(unsigned char* digest, sha512_256_state* s) {
  tinysha512_base_final(digest, SHA512_256_DIGEST_SIZE, &s->state);
}
