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
/// Interface to a SHA-512 implementation.
/*! \file */

#ifndef EPID_INTERNAL_TINYMATH_INCLUDE_TINYMATH_SHA512_H_
#define EPID_INTERNAL_TINYMATH_INCLUDE_TINYMATH_SHA512_H_
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>
#include "tinymath/sha512_base.h"

/// digest size
#define SHA512_DIGEST_SIZE (64)
/// number of words in SHA state
#define SHA512_DIGEST_WORDS SHA512_BASE_DIGEST_WORDS

/// The SHA state
typedef struct sha512_state {
  sha512_base_state state;  ///< base Sha state
} sha512_state;

/// Initializes the hash state
/*!

  \param[in,out] s
  The hash state to initialize.

  \see tinysha512_base_init
 */
void tinysha512_init(sha512_state* s);

/// Hashes data into state using SHA-512
/*!

  \param[in,out] s
  The hash state. Must be non-null or behavior is undefined.

  \param[in] data
  The data to hash into s.

  \param[in] data_length
  The size of data in bytes.

  \see tinysha512_base_update
 */
void tinysha512_update(sha512_state* s, void const* data, size_t data_length);

/// Computes the SHA-512 hash in the digest buffer
/*!

  \note Assumes SHA512_DIGEST_SIZE bytes are available to accept the
  digest.

  \param[out] digest
  The computed digest. Must be non-null or behavior is undefined.

  \param[in] s
  The hash state. Must be non-null or behavior is undefined.

  \see tinysha512_base_final
 */
void tinysha512_final(unsigned char* digest, sha512_state* s);

#ifdef __cplusplus
}
#endif
#endif  // EPID_INTERNAL_TINYMATH_INCLUDE_TINYMATH_SHA512_H_
