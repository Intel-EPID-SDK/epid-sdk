/*############################################################################
  # Copyright 2016-2019 Intel Corporation
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
/// EpidNrProve implementation.
/*! \file */
#include "epid/member/split/nrprove.h"

#include <stddef.h>
#include <stdint.h>

#include "common/endian_convert.h"
#include "common/epid2params.h"
#include "common/hashsize.h"
#include "epid/member/split/context.h"
#include "epid/member/split/nrprove_commitment.h"
#include "epid/member/split/privateexp.h"
#include "epid/member/split/tpm2/commit.h"
#include "epid/member/split/tpm2/keyinfo.h"
#include "epid/member/split/tpm2/sign.h"
#include "epid/stdtypes.h"
#include "epid/types.h"
#include "ippmath/ecgroup.h"
#include "ippmath/finitefield.h"
#include "ippmath/memory.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

/// Count of elements in array
#define COUNT_OF(A) (sizeof(A) / sizeof((A)[0]))

static bool IsIdentity(G1ElemStr const* elem_str) {
  unsigned char* bytes = (unsigned char*)elem_str;
  if (!bytes) {
    return false;
  } else {
    size_t i = 0;
    for (i = 0; i < sizeof(*elem_str); i++) {
      if (0 != bytes[i]) return false;
    }
  }
  return true;
}

/// Sha Digest Element
typedef union sha_digest {
  uint8_t sha512_digest[EPID_SHA512_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t sha384_digest[EPID_SHA384_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t sha256_digest[EPID_SHA256_DIGEST_BITSIZE / CHAR_BIT];
  uint8_t digest[1];  ///< Pointer to digest
} sha_digest;
#pragma pack(1)
typedef struct EpidNrProveCommitValues {
  BigNumStr noncek;  //!< random number (256-bit)
  sha_digest digest;
} EpidNrProveCommitValues;
#pragma pack()
EpidStatus EpidNrProve(MemberCtx const* ctx, void const* msg, size_t msg_len,
                       void const* basename, size_t basename_len,
                       BasicSignature const* sig, SigRlEntry const* sigrl_entry,
                       SplitNrProof* proof) {
  EpidStatus sts = kEpidErr;

  EcPoint* B = NULL;
  EcPoint* K = NULL;
  EcPoint* rlB = NULL;
  EcPoint* rlK = NULL;
  EcPoint* t = NULL;  // temp value in G1 either T, R1, R2
  EcPoint* k_tpm = NULL;
  EcPoint* l_tpm = NULL;
  EcPoint* e_tpm = NULL;
  EcPoint* D = NULL;
  FfElement* y2 = NULL;
  uint8_t* s2 = NULL;
  FfElement* mu = NULL;
  FfElement* nu = NULL;
  FfElement* rmu = NULL;
  EpidNrProveCommitValues commit_values = {0};
  FfElement* noncek = NULL;

  FfElement* t2 = NULL;  // temporary for multiplication

  BigNumStr mu_str = {0};
  BigNumStr nu_str = {0};
  BigNumStr rmu_str = {0};
  uint16_t counter =
      0;  ///< TPM counter pointing to Nr Proof related random value
  bool is_counter_set = false;

  if (!ctx || (0 != msg_len && !msg) || !sig || !sigrl_entry || !proof)
    return kEpidBadArgErr;
  if (!basename || 0 == basename_len) {
    // basename should not be empty
    return kEpidBadArgErr;
  }
  if (!ctx->epid2_params) return kEpidBadArgErr;

  do {
    NrProveCommitOutput commit_out = {0};
    FiniteField* Fp = ctx->epid2_params->Fp;
    FiniteField* Fq = ctx->epid2_params->Fq;
    EcGroup* G1 = ctx->epid2_params->G1;
    BitSupplier rnd_func = ctx->rnd_func;
    void* rnd_param = ctx->rnd_param;
    uint32_t i = 0;
    G1ElemStr B_str = {0};
    const BigNumStr kOne = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    FpElemStr c_str = {0};

    HashAlg hash_alg = Tpm2KeyHashAlg(ctx->f_handle);
    size_t digest_len = EpidGetHashSize(hash_alg);
    size_t commit_len = 0;

    if (sizeof(commit_values.digest) < digest_len) {
      return kEpidBadArgErr;
    }
    sts = NewEcPoint(G1, &B);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &K);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &rlB);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &rlK);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &D);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &t);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewFfElement(Fp, &y2);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &k_tpm);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &l_tpm);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &e_tpm);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewFfElement(Fp, &mu);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &nu);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &rmu);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &noncek);
    BREAK_ON_EPID_ERROR(sts);

    s2 = SAFE_ALLOC(basename_len + sizeof(i));
    if (!s2) {
      sts = kEpidMemAllocErr;
      break;
    }
    sts = ReadEcPoint(G1, &sig->K, sizeof(sig->K), K);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadEcPoint(G1, &(sigrl_entry->b), sizeof(sigrl_entry->b), rlB);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(G1, &(sigrl_entry->k), sizeof(sigrl_entry->k), rlK);
    BREAK_ON_EPID_ERROR(sts);

    // 1.  The member chooses random mu from [1, p-1].
    sts = FfGetRandom(Fp, &kOne, rnd_func, rnd_param, mu);
    BREAK_ON_EPID_ERROR(sts);
    // 2.  The member computes nu = -mu mod p.
    sts = FfNeg(Fp, mu, nu);
    BREAK_ON_EPID_ERROR(sts);
    // 3.1. The member computes D = G1.privateExp(B', f): calculate f * B'
    sts = EpidPrivateExp((MemberCtx*)ctx, rlB, ctx->f_handle, D);
    BREAK_ON_EPID_ERROR(sts);
    // 3.2.The member computes T = G1.sscmMultiExp(K', mu, D, nu):
    // T = mu * K' + (-mu * f * B')
    sts = WriteFfElement(Fp, mu, &mu_str, sizeof(mu_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, nu, &nu_str, sizeof(nu_str));
    BREAK_ON_EPID_ERROR(sts);
    {
      EcPoint const* points[2];
      BigNumStr const* exponents[2];
      points[0] = rlK;
      points[1] = D;
      exponents[0] = &mu_str;
      exponents[1] = &nu_str;
      sts = EcSscmMultiExp(G1, points, exponents, COUNT_OF(points), t);
      BREAK_ON_EPID_ERROR(sts);
      sts = WriteEcPoint(G1, t, &commit_out.T, sizeof(commit_out.T));
      BREAK_ON_EPID_ERROR(sts);
    }
    // 4.1. The member chooses rmu randomly from[1, p - 1].
    sts = FfGetRandom(Fp, &kOne, rnd_func, rnd_param, rmu);
    BREAK_ON_EPID_ERROR(sts);
    // (rf * B = L, rf * B' = E) = TPM2_Commit(P1 = B', s2 = (i || basename),
    // y2 = By)
    sts = EcHash(G1, basename, basename_len, hash_alg, B, &i);
    BREAK_ON_EPID_ERROR(sts);
    *(uint32_t*)s2 = ntohl(i);
    sts = WriteEcPoint(G1, B, &B_str, sizeof(B_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(Fq, &B_str.y, sizeof(B_str.y), y2);
    BREAK_ON_EPID_ERROR(sts);
    if (0 != memcpy_S(s2 + sizeof(i), basename_len, basename, basename_len)) {
      sts = kEpidErr;
      break;
    }
    sts =
        Tpm2Commit(ctx->tpm2_ctx, ctx->f_handle, rlB, s2,
                   basename_len + sizeof(i), y2, k_tpm, l_tpm, e_tpm, &counter);
    BREAK_ON_EPID_ERROR(sts);
    is_counter_set = true;
    // R1 = rmu * K + (-mu * L)
    sts = WriteFfElement(Fp, rmu, &rmu_str, sizeof(rmu_str));
    BREAK_ON_EPID_ERROR(sts);
    {
      EcPoint const* points[2];
      BigNumStr const* exponents[2];
      points[0] = K;
      points[1] = l_tpm;
      exponents[0] = &rmu_str;
      exponents[1] = &nu_str;
      sts = EcSscmMultiExp(G1, points, exponents, COUNT_OF(points), t);
      BREAK_ON_EPID_ERROR(sts);
      sts = WriteEcPoint(G1, t, &commit_out.R1, sizeof(commit_out.R1));
      BREAK_ON_EPID_ERROR(sts);
    }
    // R2 = rmu * K' + (-mu * E)
    {
      EcPoint const* points[2];
      BigNumStr const* exponents[2];
      points[0] = rlK;
      points[1] = e_tpm;
      exponents[0] = &rmu_str;
      exponents[1] = &nu_str;
      sts = EcSscmMultiExp(G1, points, exponents, COUNT_OF(points), t);
      BREAK_ON_EPID_ERROR(sts);
      sts = WriteEcPoint(G1, t, &commit_out.R2, sizeof(commit_out.R2));
      BREAK_ON_EPID_ERROR(sts);
    }
    // c = hashFp(p || g1 || B | K || B' || K' || T || R1 || R2 || m)
    sts = HashNrProveCommitment(Fp, hash_alg, &sig->B, &sig->K, sigrl_entry,
                                &commit_out, msg, msg_len, &c_str);
    BREAK_ON_EPID_ERROR(sts);
    // TPM2_Sign(digest = c)
    commit_len = sizeof(commit_values.noncek) + digest_len;
    if (0 != memcpy_S(commit_values.digest.digest + digest_len - sizeof(c_str),
                      sizeof(c_str), &c_str, sizeof(c_str))) {
      sts = kEpidBadArgErr;
      BREAK_ON_EPID_ERROR(sts);
    }

    sts = NewFfElement(Fp, &t2);
    BREAK_ON_EPID_ERROR(sts);
    sts = Tpm2Sign(ctx->tpm2_ctx, ctx->f_handle, &commit_values.digest,
                   digest_len, counter, noncek, t2);
    BREAK_ON_EPID_ERROR(sts);
    is_counter_set = false;
    // snu = -mu * s
    sts = FfMul(Fp, nu, t2, t2);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, t2, &proof->snu, sizeof(proof->snu));
    BREAK_ON_EPID_ERROR(sts);
    // t = hashFp(k || c)
    sts = WriteFfElement(Fp, noncek, &commit_values.noncek,
                         sizeof(commit_values.noncek));
    BREAK_ON_EPID_ERROR(sts);
    sts = FfHash(Fp, &commit_values, commit_len, hash_alg, t2);
    BREAK_ON_EPID_ERROR(sts);
    // smu = rmu + t * mu mod p
    sts = FfMul(Fp, t2, mu, t2);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfAdd(Fp, rmu, t2, t2);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, t2, &proof->smu, sizeof(proof->smu));
    BREAK_ON_EPID_ERROR(sts);

    // 10. The member outputs sigma = (T, c, smu, snu, k), a non-revoked
    //     proof. If G1.is_identity(T) = true, the member also outputs
    //     "failed".
    proof->T = commit_out.T;
    proof->c = c_str;
    sts = WriteFfElement(Fp, noncek, &proof->noncek, sizeof(proof->noncek));

    if (IsIdentity(&proof->T)) {
      sts = kEpidSigRevokedInSigRl;
      BREAK_ON_EPID_ERROR(sts);
    }

    sts = kEpidNoErr;
  } while (0);

  if (is_counter_set == true) {
    (void)Tpm2ReleaseCounter(ctx->tpm2_ctx, counter, ctx->f_handle);
  }
  SAFE_FREE(s2);
  EpidZeroMemory(&mu_str, sizeof(mu_str));
  EpidZeroMemory(&nu_str, sizeof(nu_str));
  EpidZeroMemory(&rmu_str, sizeof(rmu_str));
  DeleteFfElement(&y2);
  DeleteEcPoint(&B);
  DeleteEcPoint(&K);
  DeleteEcPoint(&rlB);
  DeleteEcPoint(&rlK);
  DeleteEcPoint(&D);
  DeleteEcPoint(&t);
  DeleteEcPoint(&e_tpm);
  DeleteEcPoint(&l_tpm);
  DeleteEcPoint(&k_tpm);
  DeleteFfElement(&mu);
  DeleteFfElement(&nu);
  DeleteFfElement(&rmu);
  DeleteFfElement(&t2);
  DeleteFfElement(&noncek);

  return sts;
}
