/*############################################################################
# Copyright 2017-2018 Intel Corporation
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
/// Implementation of Fp math
/*! \file */

#include "epid/member/tiny/math/fp.h"

#include <limits.h>  // for CHAR_BIT
#include "epid/member/tiny/math/mathtypes.h"
#include "epid/member/tiny/math/serialize.h"
#include "epid/member/tiny/math/vli.h"

/// A security parameter. In this version of Intel(R) EPID SDK, slen = 128
#define EPID_SLEN 128
/// number of bits required for random generation in Fp
#define RAND_NUM_BITS (sizeof(FpElem) * CHAR_BIT + EPID_SLEN)

static VeryLargeInt const epid20_p = {{0xD10B500D, 0xF62D536C, 0x1299921A,
                                       0x0CDC65FB, 0xEE71A49E, 0x46E5F25E,
                                       0xFFFCF0CD, 0xFFFFFFFF}};
static FpElem const one = {{{1, 0, 0, 0, 0, 0, 0, 0}}};
static VeryLargeInt const p_minus_one = {{0xD10B500C, 0xF62D536C, 0x1299921A,
                                          0x0CDC65FB, 0xEE71A49E, 0x46E5F25E,
                                          0xFFFCF0CD, 0xFFFFFFFF}};

void FpFromHash(FpElem* result, unsigned char const* hash, size_t len) {
  VeryLargeIntProduct vli = {0};
  size_t i = sizeof(vli);  // temporary use as sizeof variable
  len = (len > i) ? i : len;
  for (i = 0; i < len; i++) {
    ((uint8_t*)vli.word)[len - i - 1] = hash[i];
  }
  VliModBarrett(&result->limbs, &vli, &epid20_p);
}

void FpAdd(FpElem* result, FpElem const* left, FpElem const* right) {
  VliModAdd(&result->limbs, &left->limbs, &right->limbs, &epid20_p);
}

void FpSub(FpElem* result, FpElem const* left, FpElem const* right) {
  VliModSub(&result->limbs, &left->limbs, &right->limbs, &epid20_p);
}

void FpMul(FpElem* result, FpElem const* left, FpElem const* right) {
  VliModMul(&result->limbs, &left->limbs, &right->limbs, &epid20_p);
}

void FpExp(FpElem* result, FpElem const* base, VeryLargeInt const* exp) {
  VliModExp(&result->limbs, &base->limbs, exp, &epid20_p);
}

void FpNeg(FpElem* result, FpElem const* in) {
  VliCondSet(&result->limbs, &epid20_p, &in->limbs, VliIsZero(&in->limbs));
  VliSub(&result->limbs, &epid20_p, &result->limbs);
}

void FpInv(FpElem* result, FpElem const* in) {
  VliModInv(&result->limbs, &in->limbs, &epid20_p);
}

int FpRand(FpElem* result, BitSupplier rnd_func, void* rnd_param) {
  VeryLargeIntProduct res = {{0}};
  uint8_t* num = (uint8_t*)&res + sizeof(res) - RAND_NUM_BITS / 8;
  if (rnd_func((unsigned int*)num, RAND_NUM_BITS, rnd_param)) {
    return 0;
  }
  VliProductDeserialize(&res, (OctStr512*)&res);
  VliModBarrettSecure(&result->limbs, &res, &epid20_p);
  return 1;
}

int FpRandNonzero(FpElem* result, BitSupplier rnd_func, void* rnd_param) {
  VeryLargeIntProduct res = {{0}};
  uint8_t* num = (uint8_t*)&res + sizeof(res) - RAND_NUM_BITS / 8;
  if (rnd_func((unsigned int*)num, RAND_NUM_BITS, rnd_param)) {
    return 0;
  }
  VliProductDeserialize(&res, (OctStr512*)&res);
  VliModBarrettSecure(&result->limbs, &res, &p_minus_one);
  // (t mod(p-1)) + 1 gives number in [1,p-1]
  FpAdd(result, result, &one);
  return 1;
}

int FpInField(FpElem const* in) { return (VliCmp(&in->limbs, &epid20_p) < 0); }

int FpEq(FpElem const* left, FpElem const* right) {
  return (VliCmp(&left->limbs, &right->limbs) == 0);
}

void FpSet(FpElem* result, uint32_t in) {
  FpClear(result);
  result->limbs.word[0] = in;
}

void FpClear(FpElem* result) { VliClear(&result->limbs); }
