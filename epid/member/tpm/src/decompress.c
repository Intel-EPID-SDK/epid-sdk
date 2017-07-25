/*############################################################################
  # Copyright 2017 Intel Corporation
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
/// TPM key decompression implementation
/*! \file */

#include "epid/member/tpm/decompress.h"

#include "epid/member/tpm/src/types.h"
#include "epid/common/src/epid2params.h"
#include "epid/common/math/bignum.h"
#include "epid/common/math/ecgroup.h"
#include "epid/common/math/finitefield.h"
#include "epid/common/math/pairing.h"
#include "epid/common/math/hash.h"
#include "epid/common/src/memory.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

/// Implements the derivation method used by private key decompression
/// Derives two integers x, f between [1, p-1] from the seed value
static EpidStatus DeriveXF(Seed const* seed, FpElemStr const* p, FpElemStr* x,
                           FpElemStr* f);

EpidStatus TpmDecompressKey(TpmCtx* ctx, G1ElemStr const* h1_str,
                            G2ElemStr const* w_str, FqElemStr const* Ax_str,
                            G1ElemStr* A_str, FpElemStr* x_str) {
  EpidStatus sts = kEpidErr;

  FfElement* Ax = NULL;
  EcPoint* A = NULL;
  EcPoint* t1 = NULL;
  EcPoint* w = NULL;
  FfElement* t3 = NULL;
  EcPoint* h1 = NULL;
  EcPoint* t2 = NULL;
  FfElement* t4 = NULL;
  BigNum* bn_pminus1 = NULL;
  FpElemStr f_str = {0};

  if (!ctx || !h1_str || !w_str || !Ax_str || !A_str || !x_str ||
      !ctx->epid2_params) {
    return kEpidBadArgErr;
  }

  do {
    EcGroup* G1 = ctx->epid2_params->G1;
    EcGroup* G2 = ctx->epid2_params->G2;
    FiniteField* GT = ctx->epid2_params->GT;
    FiniteField* Fp = ctx->epid2_params->Fp;
    FiniteField* Fq = ctx->epid2_params->Fq;
    EcPoint const* g1 = ctx->epid2_params->g1;
    EcPoint const* g2 = ctx->epid2_params->g2;
    BigNum const* p = ctx->epid2_params->p;
    PairingState* ps_ctx = ctx->epid2_params->pairing_state;
    Seed const* seed = &ctx->secret.seed;
    FfElement* f = (FfElement*)ctx->secret.f;

    FpElemStr p_str = {0};
    FpElemStr temp_x_str = {0};
    uint8_t bn_one_str = 1;
    bool is_valid = false;

    // 1. The member derives x and f from seed. The derivation
    //    function must be the same as the one used in the key
    //    generation above.
    sts = WriteBigNum(p, sizeof(p_str), &p_str);
    BREAK_ON_EPID_ERROR(sts);
    sts = DeriveXF(seed, &p_str, &temp_x_str, &f_str);
    BREAK_ON_EPID_ERROR(sts);
    // 2. The member computes A = G1.makePoint(A.x).
    sts = NewFfElement(Fq, &Ax);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(Fq, Ax_str, sizeof(*Ax_str), Ax);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &A);
    BREAK_ON_EPID_ERROR(sts);
    sts = EcMakePoint(G1, Ax, A);
    BREAK_ON_EPID_ERROR(sts);
    // 3. The member tests whether (A, x, f) is a valid Intel(R) EPID
    //    private key as follows:
    //   a. It computes t1 = G2.sscmExp(g2, x).
    sts = NewEcPoint(G2, &t1);
    BREAK_ON_EPID_ERROR(sts);
    sts = EcSscmExp(G2, g2, (BigNumStr const*)&temp_x_str, t1);
    BREAK_ON_EPID_ERROR(sts);
    //   b. It computes t1 = G2.mul(t1, w).
    sts = NewEcPoint(G2, &w);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(G2, w_str, sizeof(*w_str), w);
    BREAK_ON_EPID_ERROR(sts);
    sts = EcMul(G2, t1, w, t1);
    BREAK_ON_EPID_ERROR(sts);
    //   c. It computes t3 = pairing(A, t1).
    sts = NewFfElement(GT, &t3);
    BREAK_ON_EPID_ERROR(sts);
    sts = Pairing(ps_ctx, A, t1, t3);
    BREAK_ON_EPID_ERROR(sts);
    //   d. It computes t2 = G1.sscmExp(h1, f).
    sts = NewEcPoint(G1, &h1);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(G1, h1_str, sizeof(*h1_str), h1);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &t2);
    BREAK_ON_EPID_ERROR(sts);
    sts = EcSscmExp(G1, h1, (BigNumStr const*)&f_str, t2);
    BREAK_ON_EPID_ERROR(sts);
    //   e. It computes t2 = G1.mul(t2, g1).
    sts = EcMul(G1, t2, g1, t2);
    BREAK_ON_EPID_ERROR(sts);
    //   f. It computes t4 = pairing(t2, g2).
    sts = NewFfElement(GT, &t4);
    BREAK_ON_EPID_ERROR(sts);
    sts = Pairing(ps_ctx, t2, g2, t4);
    BREAK_ON_EPID_ERROR(sts);
    //   g. If GT.isEqual(t3, t4) = false
    sts = FfIsEqual(GT, t3, t4, &is_valid);
    BREAK_ON_EPID_ERROR(sts);
    if (!is_valid) {
      //   i.   It computes t3 = GT.exp(t3, p-1).
      sts = NewBigNum(sizeof(BigNumStr), &bn_pminus1);
      BREAK_ON_EPID_ERROR(sts);
      sts = ReadBigNum(&bn_one_str, sizeof(bn_one_str), bn_pminus1);
      BREAK_ON_EPID_ERROR(sts);
      sts = BigNumSub(p, bn_pminus1, bn_pminus1);
      BREAK_ON_EPID_ERROR(sts);
      sts = FfExp(GT, t3, bn_pminus1, t3);
      BREAK_ON_EPID_ERROR(sts);
      //   ii.  If GT.isEqual(t3, t4) = false again, it reports bad
      //        Intel(R) EPID private key and exits.
      sts = FfIsEqual(GT, t3, t4, &is_valid);
      BREAK_ON_EPID_ERROR(sts);
      if (!is_valid) {
        sts = kEpidBadArgErr;  // Invalid Member key
        BREAK_ON_EPID_ERROR(sts);
      }
      //   iii. It sets A = G1.inverse(A).
      sts = EcInverse(G1, A, A);
      BREAK_ON_EPID_ERROR(sts);
    }
    // 4. The decompressed Intel(R) EPID private key is (gid, A, x, f).
    sts = WriteEcPoint(G1, A, A_str, sizeof(*A_str));
    BREAK_ON_EPID_ERROR(sts);
    *x_str = temp_x_str;
    sts = ReadFfElement(Fp, &f_str, sizeof(f_str), f);
    BREAK_ON_EPID_ERROR(sts);

    sts = kEpidNoErr;
  } while (0);

  EpidZeroMemory(&f_str, sizeof(f_str));
  DeleteFfElement(&Ax);
  DeleteEcPoint(&A);
  DeleteEcPoint(&t1);
  DeleteEcPoint(&w);
  DeleteFfElement(&t3);
  DeleteEcPoint(&h1);
  DeleteEcPoint(&t2);
  DeleteFfElement(&t4);
  DeleteBigNum(&bn_pminus1);

  return sts;
}

/// Hash message buffer
typedef struct HashMsg {
  /// Message to be hashed
  char data[11];
} HashMsg;

static EpidStatus DeriveXF(Seed const* seed, FpElemStr const* p, FpElemStr* x,
                           FpElemStr* f) {
  EpidStatus sts = kEpidErr;

  BigNum* bn_x = 0;
  BigNum* bn_f = 0;
  BigNum* bn_p = 0;

#pragma pack(1)
  struct {
    Seed seed;
    HashMsg msg;
  } hashbuf;
#pragma pack()

  do {
    HashMsg msgstr = {{
        0x00, 0x45, 0x43, 0x43, 0x2d, 0x53, 0x61, 0x66, 0x65, 0x49, 0x44,
    }};

    Sha256Digest digest[2] = {0};
    uint8_t str512[512 / 8] = {0};

    sts = NewBigNum(sizeof(*p), &bn_p);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadBigNum(p, sizeof(*p), bn_p);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewBigNum(sizeof(digest), &bn_x);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewBigNum(sizeof(digest), &bn_f);
    BREAK_ON_EPID_ERROR(sts);

    // compute x
    hashbuf.seed = *seed;
    hashbuf.msg = msgstr;
    hashbuf.msg.data[0] = 0x06;
    sts = Sha256MessageDigest(&hashbuf, sizeof(hashbuf), &digest[0]);
    BREAK_ON_EPID_ERROR(sts);
    hashbuf.msg.data[0] = 0x07;
    sts = Sha256MessageDigest(&hashbuf, sizeof(hashbuf), &digest[1]);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadBigNum(&digest, sizeof(digest), bn_x);
    BREAK_ON_EPID_ERROR(sts);

    sts = BigNumMod(bn_x, bn_p, bn_x);
    BREAK_ON_EPID_ERROR(sts);

    sts = WriteBigNum(bn_x, sizeof(str512), str512);
    BREAK_ON_EPID_ERROR(sts);

    *x = *(FpElemStr*)&str512[sizeof(str512) / 2];

    // compute f
    hashbuf.seed = *seed;
    hashbuf.msg = msgstr;
    hashbuf.msg.data[0] = 0x08;
    sts = Sha256MessageDigest(&hashbuf, sizeof(hashbuf), &digest[0]);
    BREAK_ON_EPID_ERROR(sts);
    hashbuf.msg.data[0] = 0x09;
    sts = Sha256MessageDigest(&hashbuf, sizeof(hashbuf), &digest[1]);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadBigNum(&digest, sizeof(digest), bn_f);
    BREAK_ON_EPID_ERROR(sts);

    sts = BigNumMod(bn_f, bn_p, bn_f);
    BREAK_ON_EPID_ERROR(sts);

    sts = WriteBigNum(bn_f, sizeof(str512), str512);
    BREAK_ON_EPID_ERROR(sts);

    *f = *(FpElemStr*)&str512[sizeof(str512) / 2];

    sts = kEpidNoErr;
  } while (0);

  EpidZeroMemory(&hashbuf.seed, sizeof(hashbuf.seed));
  DeleteBigNum(&bn_x);
  DeleteBigNum(&bn_f);
  DeleteBigNum(&bn_p);

  return sts;
}
