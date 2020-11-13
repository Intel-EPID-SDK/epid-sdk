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
/// Implementation of de/serialize functionality.
/*! \file */

#include "tinymath/serialize.h"
#include <stddef.h>
#include <stdint.h>
#include "epid/types.h"
#include "tinymath/mathtypes.h"
#include "tinystdlib/endian.h"
#include "tinystdlib/tiny_stdlib.h"

/// Count of elements in array
#define COUNT_OF(a) (sizeof(a) / sizeof((a)[0]))

#if !defined(UNOPTIMIZED_SERIALIZATION)
void SwapNativeAndPortableLayout(void* dest, size_t dest_size, void const* src,
                                 size_t src_size) {
  size_t i, j;
#if defined(DEBUG)
  if (dest_size != src_size || 0 != src_size % 32) {
    memset(dest, 0xff, dest_size);
    return;
  }
#else   // defined(DEBUG)
  (void)dest_size;
#endif  // defined(DEBUG)
  for (i = 0; i < src_size; i += 32) {
    for (j = 0; j < 32 / 2; j += sizeof(uint32_t)) {
      uint32_t tmp = htobe32(
          *(uint32_t*)((uint8_t*)src + i + j));  // handle src==dest case
      *(uint32_t*)((uint8_t*)dest + i + j) =
          htobe32(*(uint32_t*)((uint8_t*)src + i + 32 - sizeof(uint32_t) - j));
      *(uint32_t*)((uint8_t*)dest + i + 32 - sizeof(uint32_t) - j) = tmp;
    }
  }
}
#endif  // !defined(UNOPTIMIZED_SERIALIZATION)

void* Uint32Serialize(OctStr32* dest, uint32_t src) {
  *(uint32_t*)dest = htobe32(src);
  return dest->data + 4;
}

void const* Uint32Deserialize(uint32_t* dest, OctStr32 const* src) {
  *dest = htobe32(*(uint32_t*)src);
  return src->data + 4;
}

void* VliSerialize(BigNumStr* dest, VeryLargeInt const* src) {
#if defined(UNOPTIMIZED_SERIALIZATION)
  size_t i;
  for (i = COUNT_OF(src->word) - 1; i >= 0; i--) {
    dest = Uint32Serialize((OctStr32*)dest, src->word[i]);
  }
  return dest;
#else   // defined(UNOPTIMIZED_SERIALIZATION)
  SwapNativeAndPortableLayout(dest, sizeof(*dest), src, sizeof(*src));
  return dest + 1;
#endif  // defined(UNOPTIMIZED_SERIALIZATION)
}

void const* VliDeserialize(VeryLargeInt* dest, BigNumStr const* src) {
#if defined(UNOPTIMIZED_SERIALIZATION)
  size_t i;
  for (i = COUNT_OF(dest->word) - 1; i >= 0; i--) {
    src = Uint32Deserialize(dest->word + i, (OctStr32 const*)src);
  }
  return src;
#else   // defined(UNOPTIMIZED_SERIALIZATION)
  SwapNativeAndPortableLayout(dest, sizeof(*dest), src, sizeof(*src));
  return src + 1;
#endif  // defined(UNOPTIMIZED_SERIALIZATION)
}

void const* VliProductDeserialize(VeryLargeIntProduct* dest,
                                  OctStr512 const* src) {
  size_t i;
  uint32_t* src_words = (uint32_t*)src;
  for (i = 0; i < COUNT_OF(dest->word) / 2; i++) {
    // doing counterpart as unsigned int is safe since right side is always
    // larger than zero
    size_t counterpart = COUNT_OF(dest->word) - i - 1;
    uint32_t tmp = htobe32(src_words[i]);
    dest->word[i] = htobe32(src_words[counterpart]);
    dest->word[counterpart] = tmp;
  }
  return src + 1;
}

void* FqSerialize(FqElemStr* dest, FqElem const* src) {
#if defined(UNOPTIMIZED_SERIALIZATION)
  dest = VliSerialize((BigNumStr*)dest, &src->limbs);
  return dest;
#else   // defined(UNOPTIMIZED_SERIALIZATION)
  SwapNativeAndPortableLayout(dest, sizeof(*dest), src, sizeof(*src));
  return dest + 1;
#endif  // defined(UNOPTIMIZED_SERIALIZATION)
}

void const* FqDeserialize(FqElem* dest, FqElemStr const* src) {
#if defined(UNOPTIMIZED_SERIALIZATION)
  src = VliDeserialize(&dest->limbs, (BigNumStr const*)src);
  return src;
#else   // defined(UNOPTIMIZED_SERIALIZATION)
  SwapNativeAndPortableLayout(dest, sizeof(*dest), src, sizeof(*src));
  return src + 1;
#endif  // defined(UNOPTIMIZED_SERIALIZATION)
}

#if defined(UNOPTIMIZED_SERIALIZATION)
static void* Fq2Serialize(Fq2ElemStr* dest, Fq2Elem const* src) {
  FqSerialize(&dest->a[0], &src->x0);
  FqSerialize(&dest->a[1], &src->x1);
  return dest + sizeof(*dest);
}

static void const* Fq2Deserialize(Fq2Elem* dest, Fq2ElemStr const* src) {
  FqDeserialize(&dest->x0, &src->a[0]);
  FqDeserialize(&dest->x1, &src->a[1]);
  return src + sizeof(*src);
}

static void* Fq6Serialize(Fq6ElemStr* dest, Fq6Elem const* src) {
  Fq2Serialize(&dest->a[0], &src->y0);
  Fq2Serialize(&dest->a[1], &src->y1);
  Fq2Serialize(&dest->a[2], &src->y2);
  return dest + sizeof(*dest);
}

static void const* Fq6Deserialize(Fq6Elem* dest, Fq6ElemStr const* src) {
  Fq2Deserialize(&dest->y0, &src->a[0]);
  Fq2Deserialize(&dest->y1, &src->a[1]);
  Fq2Deserialize(&dest->y2, &src->a[2]);
  return src + sizeof(*src);
}
#endif  // defined(UNOPTIMIZED_SERIALIZATION)

void const* Fq12Deserialize(Fq12Elem* dest, Fq12ElemStr const* src) {
#if defined(UNOPTIMIZED_SERIALIZATION)
  Fq6Deserialize(&dest->z0, &src->a[0]);
  Fq6Deserialize(&dest->z1, &src->a[1]);
  return src + sizeof(*src);
#else   // defined(UNOPTIMIZED_SERIALIZATION)
  SwapNativeAndPortableLayout(dest, sizeof(*dest), src, sizeof(*src));
  return src + 1;
#endif  // defined(UNOPTIMIZED_SERIALIZATION)
}

void* Fq12Serialize(Fq12ElemStr* dest, Fq12Elem const* src) {
#if defined(UNOPTIMIZED_SERIALIZATION)
  Fq6Serialize(&dest->a[0], &src->z0);
  Fq6Serialize(&dest->a[1], &src->z1);
  return dest + sizeof(*dest);
#else   // defined(UNOPTIMIZED_SERIALIZATION)
  SwapNativeAndPortableLayout(dest, sizeof(*dest), src, sizeof(*src));
  return dest + 1;
#endif  // defined(UNOPTIMIZED_SERIALIZATION)
}

void* FpSerialize(FpElemStr* dest, FpElem const* src) {
#if defined(UNOPTIMIZED_SERIALIZATION)
  dest = VliSerialize((BigNumStr*)dest, &src->limbs);
  return dest;
#else   // defined(UNOPTIMIZED_SERIALIZATION)
  SwapNativeAndPortableLayout(dest, sizeof(*dest), src, sizeof(*src));
  return dest + 1;
#endif  // defined(UNOPTIMIZED_SERIALIZATION)
}

void const* FpDeserialize(FpElem* dest, FpElemStr const* src) {
#if defined(UNOPTIMIZED_SERIALIZATION)
  src = VliDeserialize(&dest->limbs, (BigNumStr const*)src);
  return src;
#else   // defined(UNOPTIMIZED_SERIALIZATION)
  SwapNativeAndPortableLayout(dest, sizeof(*dest), src, sizeof(*src));
  return src + 1;
#endif  // defined(UNOPTIMIZED_SERIALIZATION)
}

void* EFqSerialize(G1ElemStr* dest, EccPointFq const* src) {
#if defined(UNOPTIMIZED_SERIALIZATION)
  dest = FqSerialize((FqElemStr*)dest, &src->x);
  dest = FqSerialize((FqElemStr*)dest, &src->y);
  return dest;
#else   // defined(UNOPTIMIZED_SERIALIZATION)
  SwapNativeAndPortableLayout(dest, sizeof(*dest), src, sizeof(*src));
  return dest + 1;
#endif  // defined(UNOPTIMIZED_SERIALIZATION)
}

void const* EFqDeserialize(EccPointFq* dest, G1ElemStr const* src) {
#if defined(UNOPTIMIZED_SERIALIZATION)
  src = FqDeserialize(&dest->x, (FqElemStr const*)src);
  src = FqDeserialize(&dest->y, (FqElemStr const*)src);
  return src;
#else   // defined(UNOPTIMIZED_SERIALIZATION)
  SwapNativeAndPortableLayout(dest, sizeof(*dest), src, sizeof(*src));
  return src + 1;
#endif  // defined(UNOPTIMIZED_SERIALIZATION)
}

void* EFq2Serialize(G2ElemStr* dest, EccPointFq2 const* src) {
#if defined(UNOPTIMIZED_SERIALIZATION)
  dest = FqSerialize((FqElemStr*)dest, &src->x.x0);
  dest = FqSerialize((FqElemStr*)dest, &src->x.x1);
  dest = FqSerialize((FqElemStr*)dest, &src->y.x0);
  dest = FqSerialize((FqElemStr*)dest, &src->y.x1);
  return dest;
#else   // defined(UNOPTIMIZED_SERIALIZATION)
  SwapNativeAndPortableLayout(dest, sizeof(*dest), src, sizeof(*src));
  return dest + 1;
#endif  // defined(UNOPTIMIZED_SERIALIZATION)
}

void const* EFq2Deserialize(EccPointFq2* dest, G2ElemStr const* src) {
#if defined(UNOPTIMIZED_SERIALIZATION)
  src = FqDeserialize(&dest->x.x0, (FqElemStr const*)src);
  src = FqDeserialize(&dest->x.x1, (FqElemStr const*)src);
  src = FqDeserialize(&dest->y.x0, (FqElemStr const*)src);
  src = FqDeserialize(&dest->y.x1, (FqElemStr const*)src);
  return src;
#else   // defined(UNOPTIMIZED_SERIALIZATION)
  SwapNativeAndPortableLayout(dest, sizeof(*dest), src, sizeof(*src));
  return src + 1;
#endif  // defined(UNOPTIMIZED_SERIALIZATION)
}
