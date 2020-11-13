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
/// Tiny implementation of standard library memcpy for 32-bit ARM
/*! \file */

#include "tinystdlib/tiny_stdlib.h"

#ifdef SHARED
#if defined(__arm__) && !defined(__aarch64__)  // only for 32-bit ARM

#include <stdint.h>
#ifndef RSIZE_MAX
#define RSIZE_MAX ((SIZE_MAX) >> 1)
#endif

/// Copies bytes between buffers
/*!
  Copies count bytes from src to dest. If the source and destination
  overlap, the behavior is undefined.

  \param[out] dest
  pointer to the object to copy to
  of the destination object)
  \param[in] src
  pointer to the object to copy from
  \param[in] count
  number of bytes to copy

  \returns dest
 */
void* memcpy(void* dest, void const* src, size_t count) {
  size_t i;
  if (!dest) {
    return dest;
  }
  if (!src || count > RSIZE_MAX) {
    return dest;
  }
  if (count > (dest > src ? ((uintptr_t)dest - (uintptr_t)src)
                          : ((uintptr_t)src - (uintptr_t)dest))) {
    return dest;
  }

  for (i = 0; i < count; i++) ((uint8_t*)dest)[i] = ((uint8_t*)src)[i];
  return dest;
}

#endif  // defined(__arm__) && !defined(__aarch64__)
#endif  // SHARED
