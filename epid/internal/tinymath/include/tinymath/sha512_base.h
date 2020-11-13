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
/// Interface to a base SHA-512 implementation.
/*!
 * \file
 *
 * Algorithms of sha-384, sha-512 and sha-512/256 are the same, but differ in
 * digest size. Functions of this file are used in those functions
 */

#ifndef EPID_INTERNAL_TINYMATH_INCLUDE_TINYMATH_SHA512_BASE_H_
#define EPID_INTERNAL_TINYMATH_INCLUDE_TINYMATH_SHA512_BASE_H_
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdint.h>

/// block size
#define SHA512_BASE_BLOCK_SIZE (128)
/// number of words in SHA state
#define SHA512_BASE_DIGEST_WORDS (8)

/// The SHA state
typedef struct sha512_base_state {
  uint64_t iv[SHA512_BASE_DIGEST_WORDS];  ///< initialization vector
  uint64_t bits_hashed;                   ///< number of bits hashed so far
  unsigned char leftover[SHA512_BASE_BLOCK_SIZE];  ///< data blocks
  unsigned int leftover_offset;  ///< number of data blocks used so far
} sha512_base_state;

/// Initializes the hash state
/*!

  \param[in,out] s
  The hash state to initialize.
  \param[in] iv
  Initialization vector.
 */
void tinysha512_base_init(sha512_base_state* s, uint64_t const* iv);

/// Hashes data into state using SHA-512
/*!

  \warning
  The state buffer 'leftover' is left in memory after processing. If
  your application intends to have sensitive data in this buffer,
  remember to erase it after the data has been processed

  \param[in,out] s
  The hash state. Must be non-null or behavior is undefined.

  \param[in] data
  The data to hash into s.

  \param[in] data_length
  The size of data in bytes.
 */
void tinysha512_base_update(sha512_base_state* s, void const* data,
                            size_t data_length);

/// Computes the SHA-512 hash in the digest buffer of given size
/*!

  \warning
  The state buffer 'leftover' is left in memory after processing. If
  your application intends to have sensitive data in this buffer,
  remember to erase it after the data has been processed

  \param[out] digest
  The computed digest. Must be non-null or behavior is undefined.

  \param[in] digest_size
  Size of the digest.

  \param[in] s
  The hash state. Must be non-null or behavior is undefined.
 */
void tinysha512_base_final(unsigned char* digest, size_t digest_size,
                           sha512_base_state* s);

#ifdef __cplusplus
}
#endif
#endif  // EPID_INTERNAL_TINYMATH_INCLUDE_TINYMATH_SHA512_BASE_H_
