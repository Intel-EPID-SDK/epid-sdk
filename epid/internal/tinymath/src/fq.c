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
/// Implementation of Fq math
/*! \file */

#include "tinymath/fq.h"

#include <limits.h>  // for CHAR_BIT
#include "tinymath/mathtypes.h"
#include "tinymath/serialize.h"
#include "tinymath/vli.h"

/// A security parameter. In this version of Intel(R) EPID SDK, slen = 128
#define EPID_SLEN 128
/// number of bits required for random generation in Fq
#define RAND_NUM_BITS (sizeof(FqElem) * CHAR_BIT + EPID_SLEN)

static VeryLargeInt const epid20_q = {{0xAED33013, 0xD3292DDB, 0x12980A82,
                                       0x0CDC65FB, 0xEE71A49F, 0x46E5F25E,
                                       0xFFFCF0CD, 0xFFFFFFFF}};
// precomputed (epid20_q+1)/4)
static VeryLargeInt const precomp_exp = {{0xEBB4CC05, 0xB4CA4B76, 0xC4A602A0,
                                          0xC337197E, 0xBB9C6927, 0x51B97C97,
                                          0xFFFF3C33, 0x3FFFFFFF}};

void FqFromHash(FqElem* result, unsigned char const* hash, size_t len) {
  VeryLargeIntProduct vli = {0};
  size_t i = sizeof(vli);  // temporary use as sizeof variable
  len = (len > i) ? i : len;
  for (i = 0; i < len; i++) {
    ((uint8_t*)vli.word)[len - i - 1] = hash[i];
  }
  VliModBarrett(&result->limbs, &vli, &epid20_q);
}

void FqAdd(FqElem* result, FqElem const* left, FqElem const* right) {
  VliModAdd(&result->limbs, &left->limbs, &right->limbs, &epid20_q);
}

void FqSub(FqElem* result, FqElem const* left, FqElem const* right) {
  VliModSub(&result->limbs, &left->limbs, &right->limbs, &epid20_q);
}

void FqMul(FqElem* result, FqElem const* left, FqElem const* right) {
  VliModMul(&result->limbs, &left->limbs, &right->limbs, &epid20_q);
}

void FqExp(FqElem* result, FqElem const* base, VeryLargeInt const* exp) {
  VliModExp(&result->limbs, &base->limbs, exp, &epid20_q);
}

void FqInv(FqElem* result, FqElem const* in) {
  VliModInv(&result->limbs, &in->limbs, &epid20_q);
}

void FqNeg(FqElem* result, FqElem const* in) {
  VliCondSet(&result->limbs, &epid20_q, &in->limbs, VliIsZero(&in->limbs));
  VliSub(&result->limbs, &epid20_q, &result->limbs);
}

void FqSquare(FqElem* result, FqElem const* in) {
  VliModSquare(&result->limbs, &in->limbs, &epid20_q);
}

bool FqSqrt(FqElem* result, FqElem const* in) {
  VeryLargeInt tmp;
  // Intel(R) EPID 2.0 parameter q meets q = 3 mod 4.
  // Square root can be computed as in^((q+1)/4) mod q.
  FqExp(result, in, &precomp_exp);  // result = in^((q+1)/4) mod q
  // validate sqrt exists
  VliModSquare(&tmp, &result->limbs, &epid20_q);
  return 0 == VliCmp(&tmp, &in->limbs);
}

bool FqRand(FqElem* result, BitSupplier rnd_func, void* rnd_param) {
  VeryLargeIntProduct res = {{0}};
  uint8_t* num = (uint8_t*)&res + sizeof(res) - RAND_NUM_BITS / 8;
  if (rnd_func((unsigned int*)num, RAND_NUM_BITS, rnd_param)) {
    return false;
  }
  VliProductDeserialize(&res, (OctStr512*)&res);
  VliModBarrettSecure(&result->limbs, &res, &epid20_q);
  return true;
}

bool FqInField(FqElem const* in) { return (VliCmp(&in->limbs, &epid20_q) < 0); }

bool FqIsZero(FqElem const* value) { return VliIsZero(&value->limbs); }

bool FqEq(FqElem const* left, FqElem const* right) {
  return (VliCmp(&left->limbs, &right->limbs) == 0);
}

void FqCp(FqElem* result, FqElem const* in) {
  VliSet(&result->limbs, &in->limbs);
}

void FqSet(FqElem* result, uint32_t in) {
  FqClear(result);
  result->limbs.word[0] = in;
}

void FqCondSet(FqElem* result, FqElem const* true_val, FqElem const* false_val,
               int truth_val) {
  VliCondSet(&result->limbs, &true_val->limbs, &false_val->limbs, truth_val);
}

void FqClear(FqElem* result) { VliClear(&result->limbs); }
