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
/// Interface to a SHA-384 implementation.
/*! \file */

#ifndef EPID_MEMBER_TINY_MATH_SHA384_H_
#define EPID_MEMBER_TINY_MATH_SHA384_H_

#include <stddef.h>
#include <stdint.h>
#include "epid/member/tiny/math/sha512_base.h"

/// digest size
#define SHA384_DIGEST_SIZE (48)
/// number of words in SHA state
#define SHA384_DIGEST_WORDS SHA512_BASE_DIGEST_WORDS

/// The SHA state
typedef struct sha384_state {
  sha512_base_state state;  ///< base Sha state
} sha384_state;

/// Initializes the hash state
/*!

  \param[in,out] s
  The hash state to initialize.

  \see tinysha512_base_init
 */
void tinysha384_init(sha384_state* s);

/// Hashes data into state using SHA-384
/*!

  \param[in,out] s
  The hash state. Must be non-null or behavior is undefined.

  \param[in] data
  The data to hash into s.

  \param[in] data_length
  The size of data in bytes.

  \see tinysha512_base_update
 */
void tinysha384_update(sha384_state* s, void const* data, size_t data_length);

/// Computes the SHA-384 hash in the digest buffer
/*!

  \note Assumes SHA384_DIGEST_SIZE bytes are available to accept the
  digest.

  \param[out] digest
  The computed digest. Must be non-null or behavior is undefined.

  \param[in] s
  The hash state. Must be non-null or behavior is undefined.

  \see tinysha512_base_final
 */
void tinysha384_final(unsigned char* digest, sha384_state* s);

#endif  // EPID_MEMBER_TINY_MATH_SHA384_H_
