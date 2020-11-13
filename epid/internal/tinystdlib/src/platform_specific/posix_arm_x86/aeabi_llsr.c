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
/// 64-bit Math Worker Function.
/*! \file */

#include "tinystdlib/tiny_stdlib.h"

#ifdef SHARED
#if defined(__arm__) && !defined(__aarch64__)  // only for 32-bit ARM

#include <stdint.h>

#if !defined(__BYTE_ORDER__)
#error "__BYTE_ORDER__ undefined: unable to check endianness"
#elif !defined(__ORDER_LITTLE_ENDIAN__)
#error "__ORDER_LITTLE_ENDIAN__ undefined: unable to check endianness"
#endif  // !defined(__BYTE_ORDER__)

// only supported for little-endian
#if !(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#error "Non little-endian is not supported"
#endif

int64_t __aeabi_llsr(int64_t, int);

typedef struct pair_uint32_t {
  uint32_t low;
  uint32_t high;
} pair_uint32_t;

/*
 * Shifts a 64-bit signed value right by a particular number of bits.
 */
int64_t __aeabi_llsr(int64_t value, int n) {
  union {
    int64_t value;
    pair_uint32_t pair;
  } repr = {0};  // 64-bit value representation
  if (n == 0) {
    return value;
  }
  repr.value = value;
  if (n < 32) {
    repr.pair.low = repr.pair.low >> n;
    repr.pair.low = repr.pair.low | (repr.pair.high << (32 - n));
    repr.pair.high = repr.pair.high >> n;
  } else {
    repr.pair.low = repr.pair.high >> (n - 32);
    repr.pair.high = 0;
  }
  return repr.value;
}

#endif  // defined(__arm__) && !defined(__aarch64__)
#endif  // SHARED
