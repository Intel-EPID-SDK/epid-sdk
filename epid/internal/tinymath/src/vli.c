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
/*
===============================================================================

Copyright -2020(c) 2013, Kenneth MacKay
All rights reserved.
https://github.com/kmackay/micro-ecc

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
 * Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

===============================================================================
*/
/// Implementation of Large Integer math

#include "tinymath/vli.h"
#include "tinymath/mathtypes.h"
#include "tinymath/serialize.h"

uint32_t VliAdd(VeryLargeInt* result, VeryLargeInt const* left,
                VeryLargeInt const* right) {
  uint32_t carry = 0;
  uint32_t i;
  for (i = 0; i < NUM_ECC_DIGITS; ++i) {
    uint32_t sum = left->word[i] + right->word[i] + carry;
    carry = (sum < left->word[i] ? 1 : 0) |
            (((sum == left->word[i]) && carry) ? 1 : 0);
    result->word[i] = sum;
  }
  return carry;
}

void VliModAdd(VeryLargeInt* result, VeryLargeInt const* left,
               VeryLargeInt const* right, VeryLargeInt const* mod) {
  VeryLargeInt tmp;
  uint32_t carry = VliAdd(result, left, right);
  carry = VliSub(&tmp, result, mod) - carry;
  VliCondSet(result, result, &tmp, carry);
}

uint32_t VliSub(VeryLargeInt* result, VeryLargeInt const* left,
                VeryLargeInt const* right) {
  uint32_t borrow = 0;

  int i;
  for (i = 0; i < NUM_ECC_DIGITS; ++i) {
    uint32_t diff = left->word[i] - right->word[i] - borrow;
    borrow = (diff > left->word[i] ? 1 : 0) |
             (((diff == left->word[i]) && borrow) ? 1 : 0);
    result->word[i] = diff;
  }
  return borrow;
}

void VliModSub(VeryLargeInt* result, VeryLargeInt const* left,
               VeryLargeInt const* right, VeryLargeInt const* mod) {
  VeryLargeInt tmp;
  uint32_t borrow = VliSub(result, left, right);
  VliAdd(&tmp, result, mod);
  VliCondSet(result, &tmp, result, borrow);
}

void VliMul(VeryLargeIntProduct* result, VeryLargeInt const* left,
            VeryLargeInt const* right) {
  uint64_t tmp_r1 = 0;
  uint32_t tmp_r2 = 0;
  uint32_t i, k;
  uint64_t product;
  /* Compute each digit of result in sequence, maintaining the carries. */
  for (k = 0; k < (NUM_ECC_DIGITS * 2 - 1); ++k) {
    uint32_t min_idx = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
    for (i = min_idx; i <= k && i < NUM_ECC_DIGITS && k - i < NUM_ECC_DIGITS;
         ++i) {
      product = (uint64_t)left->word[i] * right->word[k - i];
      tmp_r1 += product;
      tmp_r2 += (tmp_r1 < product ? 1 : 0);
    }
    result->word[k] = (uint32_t)tmp_r1;
    tmp_r1 = (tmp_r1 >> 32) | (((uint64_t)tmp_r2) << 32);
    tmp_r2 = 0;
  }
  result->word[NUM_ECC_DIGITS * 2 - 1] = (uint32_t)tmp_r1;
}

void VliModMul(VeryLargeInt* result, VeryLargeInt const* left,
               VeryLargeInt const* right, VeryLargeInt const* mod) {
  VeryLargeIntProduct product;
  VliMul(&product, left, right);
  VliModBarrett(result, &product, mod);
}

void VliRShift(VeryLargeInt* result, VeryLargeInt const* in, uint32_t shift) {
  uint32_t i;
  for (i = 0; i < NUM_ECC_DIGITS - 1; i++) {
    result->word[i] = (in->word[i] >> shift) | in->word[i + 1] << (32 - shift);
  }
  result->word[NUM_ECC_DIGITS - 1] = in->word[NUM_ECC_DIGITS - 1] >> shift;
}

bool VliRand(VeryLargeInt* result, BitSupplier rnd_func, void* rnd_param) {
  uint32_t t[NUM_ECC_DIGITS] = {0};
  if (rnd_func(t, sizeof(VeryLargeInt) * 8, rnd_param)) {
    return false;
  }
  VliDeserialize(result, (BigNumStr const*)t);
  return true;
}

static void vliSquare(VeryLargeIntProduct* result, VeryLargeInt const* left) {
  uint64_t tmp_r1 = 0;
  uint32_t tmp_r2 = 0;
  uint32_t i, k;
  uint64_t product;
  for (k = 0; k < NUM_ECC_DIGITS * 2 - 1; ++k) {
    uint32_t min_idx = (k < NUM_ECC_DIGITS ? 0 : (k + 1) - NUM_ECC_DIGITS);
    for (i = min_idx; i <= k && i <= k - i && k - i < NUM_ECC_DIGITS; ++i) {
      product = (uint64_t)left->word[i] * left->word[k - i];
      if (i < k - i) {
        tmp_r2 += product >> 63;
        product *= 2;
      }
      tmp_r1 += product;
      tmp_r2 += (tmp_r1 < product ? 1 : 0);
    }
    result->word[k] = (uint32_t)tmp_r1;
    tmp_r1 = (tmp_r1 >> 32) | (((uint64_t)tmp_r2) << 32);
    tmp_r2 = 0;
  }

  result->word[NUM_ECC_DIGITS * 2 - 1] = (uint32_t)tmp_r1;
}

void VliModExp(VeryLargeInt* result, VeryLargeInt const* base,
               VeryLargeInt const* exp, VeryLargeInt const* mod) {
  VeryLargeInt acc, tmp;
  VeryLargeIntProduct product;
  uint32_t j;
  int i;
  VliClear(&acc);
  acc.word[0] = 1;
  for (i = NUM_ECC_DIGITS - 1; i >= 0; i--) {
    for (j = 1U << 31; j > 0; j = j >> 1) {
      vliSquare(&product, &acc);
      VliModBarrett(&acc, &product, mod);
      VliMul(&product, &acc, base);
      VliModBarrett(&tmp, &product, mod);
      VliCondSet(&acc, &tmp, &acc, j & (exp->word[i]));
    }
  }
  VliSet(result, &acc);
}

void VliModInv(VeryLargeInt* result, VeryLargeInt const* input,
               VeryLargeInt const* mod) {
  VeryLargeInt power;
  VliSet(&power, mod);
  power.word[0] -= 2;
  VliModExp(result, input, &power, mod);
}

void VliModSquare(VeryLargeInt* result, VeryLargeInt const* input,
                  VeryLargeInt const* mod) {
  VeryLargeIntProduct product;
  vliSquare(&product, input);
  VliModBarrett(result, &product, mod);
}

/* Computes p_result = p_in << c, returning carry.
 * Can modify in place (if p_result == p_in). 0 < p_shift < 32. */
static uint32_t vliLShift(VeryLargeIntProduct* p_result,
                          VeryLargeIntProduct const* p_in, uint32_t p_shift) {
  int i;
  uint32_t carry = p_in->word[NUM_ECC_DIGITS * 2 - 1];
  for (i = NUM_ECC_DIGITS * 2 - 1; i > 0; --i)
    p_result->word[i] =
        ((p_in->word[i] << p_shift) | (p_in->word[i - 1] >> (32 - p_shift)));
  p_result->word[0] = p_in->word[0] << p_shift;
  return carry >> (32 - p_shift);
}

static void vliScalarMult(VeryLargeInt* p_result, VeryLargeInt* p_left,
                          uint32_t p_right) {
  int i;
  uint64_t tmpresult;
  uint32_t left = 0, right;
  for (i = 0; i < NUM_ECC_DIGITS - 1; i++) {
    tmpresult = p_left->word[i] * ((uint64_t)p_right);
    right = left + ((uint32_t)tmpresult);
    left = (right < left ? 1 : 0) + ((uint32_t)(tmpresult >> 32));
    p_result->word[i] = right;
  }
  p_result->word[NUM_ECC_DIGITS - 1] = left;
}

static void vliProdRShift(VeryLargeIntProduct* result,
                          VeryLargeIntProduct const* in, uint32_t shift,
                          uint32_t len) {
  uint32_t i;
  for (i = 0; i < len - 1; i++) {
    result->word[i] = (in->word[i] >> shift) | in->word[i + 1] << (32 - shift);
  }
  result->word[len - 1] = in->word[len - 1] >> shift;
}
/* WARNING THIS METHOD MAKES STRONG ASSUMPTIONS ABOUT THE INVOLVED PRIMES
 * All primes used for computations in Intel(R) EPID 2.0 begin with 32 ones.
 * This method assumes 2^256 - p_mod
 * begins with 32 zeros, and is tuned to this assumption. Violating this
 * assumption will cause it not
 * to work. It also assumes that it does not end with 32 zeros.
 */
static void VliModBarrettInternal(VeryLargeInt* result,
                                  VeryLargeIntProduct const* input,
                                  VeryLargeInt const* mod,
                                  VeryLargeIntProduct* tmpprod) {
  int i;
  VeryLargeInt negative_prime, linear;
  uint32_t carry = 0;
  VliSet((VeryLargeInt*)&tmpprod->word[0],
         (VeryLargeInt const*)&input->word[0]);
  VliSet((VeryLargeInt*)&tmpprod->word[NUM_ECC_DIGITS],
         (VeryLargeInt const*)&input->word[NUM_ECC_DIGITS]);
  // negative prime is ~q + 1, so we store this in
  for (i = 0; i < NUM_ECC_DIGITS - 1; i++) {
    negative_prime.word[i] = ~mod->word[i];
  }
  negative_prime.word[0]++;
  for (i = 0; i < NUM_ECC_DIGITS; i++) {
    vliScalarMult(&linear, &negative_prime,
                  tmpprod->word[2 * NUM_ECC_DIGITS - 1]);
    tmpprod->word[2 * NUM_ECC_DIGITS - 1] = VliAdd(
        (VeryLargeInt*)&tmpprod->word[NUM_ECC_DIGITS - 1],
        (VeryLargeInt const*)&tmpprod->word[NUM_ECC_DIGITS - 1], &linear);
    vliLShift(tmpprod, tmpprod, 31);
  }
  // shift the 256+32-NUM_ECC_DIGITS-1 bits in the largest 9 limbs back to the
  // base
  vliProdRShift(tmpprod,
                (VeryLargeIntProduct const*)&tmpprod->word[NUM_ECC_DIGITS - 1],
                (31 * 8) % 32, NUM_ECC_DIGITS + 1);
  vliScalarMult(&linear, &negative_prime, tmpprod->word[NUM_ECC_DIGITS]);
  carry = VliAdd((VeryLargeInt*)&tmpprod->word[0],
                 (VeryLargeInt const*)&tmpprod->word[0],
                 (VeryLargeInt const*)&linear);
  carry |= (-1 < VliCmp((VeryLargeInt const*)&tmpprod->word[0], mod) ? 1 : 0);
  vliScalarMult(&linear, &negative_prime, carry);
  VliAdd(result, (VeryLargeInt const*)&tmpprod->word[0], &linear);
}
void VliModBarrettSecure(VeryLargeInt* result, VeryLargeIntProduct const* input,
                         VeryLargeInt const* mod) {
  VeryLargeIntProduct tmpprod;
  VliModBarrettInternal(result, input, mod, &tmpprod);
  VliClear((VeryLargeInt*)&tmpprod.word[0]);
  VliClear((VeryLargeInt*)&tmpprod.word[NUM_ECC_DIGITS]);
}
void VliModBarrett(VeryLargeInt* result, VeryLargeIntProduct const* input,
                   VeryLargeInt const* mod) {
  VeryLargeIntProduct tmpprod;
  VliModBarrettInternal(result, input, mod, &tmpprod);
}

bool VliIsZero(VeryLargeInt const* in) {
  uint32_t i, acc = 0;
  for (i = 0; i < NUM_ECC_DIGITS; ++i) {
    acc += (in->word[i] != 0);
  }
  return (!acc);
}

uint32_t VliTestBit(VeryLargeInt const* in, uint32_t bit) {
  // bit number must be less than 32*NUM_ECC_DIGITS
  // (sizeof VeryLargeInt in bits)
  // so do: bit % 256 = bit & (256 - 1)
  // if bit > 255, expect math to fail and give incorrect results
  return (
      (in->word[(bit & (sizeof(VeryLargeInt) * 8 - 1)) >> 5] >> (bit & 31)) &
      1);  // p_bit % 32 = p_bit & 0x0000001F = 31
}

int VliCmp(VeryLargeInt const* left, VeryLargeInt const* right) {
  int i, cmp = 0;
  for (i = NUM_ECC_DIGITS - 1; i >= 0; --i) {
    cmp |= ((left->word[i] > right->word[i] ? 1 : 0) -
            (left->word[i] < right->word[i] ? 1 : 0)) *
           (!cmp);
  }
  return cmp;
}

void VliCondSet(VeryLargeInt* result, VeryLargeInt const* true_val,
                VeryLargeInt const* false_val, int truth_val) {
  int i;
  for (i = 0; i < NUM_ECC_DIGITS; i++)
    result->word[i] = (!truth_val) * false_val->word[i] +
                      (truth_val != 0) * true_val->word[i];
}

void VliSet(VeryLargeInt* result, VeryLargeInt const* in) {
  uint32_t i;
  for (i = 0; i < NUM_ECC_DIGITS; ++i) {
    result->word[i] = in->word[i];
  }
}

void VliClear(VeryLargeInt* result) {
  uint32_t i;
  for (i = 0; i < NUM_ECC_DIGITS; ++i) {
    result->word[i] = 0;
  }
}
