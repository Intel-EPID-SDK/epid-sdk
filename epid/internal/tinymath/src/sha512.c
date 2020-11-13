/*############################################################################
# Copyright 2017-2020 Intel Corporation
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
/// A SHA-512 implementation.
/*! \file */

#include <stdint.h>

#include "tinymath/sha512.h"
#include "tinystdlib/tiny_stdlib.h"

static const uint64_t kIv512[SHA512_DIGEST_WORDS] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
void tinysha512_init(sha512_state* s) {
  tinysha512_base_init(&s->state, kIv512);
}

void tinysha512_update(sha512_state* s, void const* data, size_t data_length) {
  tinysha512_base_update(&s->state, data, data_length);
}

void tinysha512_final(unsigned char* digest, sha512_state* s) {
  tinysha512_base_final(digest, SHA512_DIGEST_SIZE, &s->state);
}
