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
/// TPM NrProve implementation
/*! \file */

#include "epid/member/tpm/nrprove.h"

#include "epid/common/math/ecgroup.h"
#include "epid/common/math/finitefield.h"
#include "epid/member/tpm/src/types.h"
#include "epid/common/src/epid2params.h"
#include "epid/common/src/memory.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

/// Count of elements in array
#define COUNT_OF(A) (sizeof(A) / sizeof((A)[0]))

EpidStatus TpmNrProveCommit(TpmCtx* ctx, G1ElemStr const* B_str,
                            G1ElemStr const* K_str,
                            SigRlEntry const* sigrl_entry,
                            NrProveCommitOutput* commit_out) {
  EpidStatus sts = kEpidErr;

  EcPoint* B = NULL;  // Also reused for B'
  EcPoint* K = NULL;  // Also reused for K'
  EcPoint* t = NULL;  // temp value in G1 either T, R1, R2

  BigNumStr mu_str = {0};
  BigNumStr nu_str = {0};
  BigNumStr rmu_str = {0};
  BigNumStr rnu_str = {0};

  if (!ctx || !sigrl_entry || !commit_out || !ctx->epid2_params) {
    return kEpidBadArgErr;
  }

  do {
    FiniteField* Fp = ctx->epid2_params->Fp;
    EcGroup* G1 = ctx->epid2_params->G1;
    BitSupplier rnd_func = ctx->rnd_func;
    void* rnd_param = ctx->secret.rnd_param;
    FfElement const* f = ctx->secret.f;
    FfElement* mu = ctx->secret.mu;
    FfElement* nu = ctx->secret.nu;
    FfElement* rmu = ctx->secret.rmu;
    FfElement* rnu = ctx->secret.rnu;
    const BigNumStr one = {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};

    sts = NewEcPoint(G1, &B);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &K);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &t);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadEcPoint(G1, B_str, sizeof(*B_str), B);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(G1, K_str, sizeof(*K_str), K);
    BREAK_ON_EPID_ERROR(sts);

    // 1.  The member chooses random mu from [1, p-1].
    sts = FfGetRandom(Fp, &one, rnd_func, rnd_param, mu);
    BREAK_ON_EPID_ERROR(sts);
    // 2.  The member computes nu = (- f * mu) mod p.
    sts = FfMul(Fp, mu, f, nu);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfNeg(Fp, nu, nu);
    BREAK_ON_EPID_ERROR(sts);
    // 4.  The member chooses rmu, rnu randomly from [1, p-1].
    sts = FfGetRandom(Fp, &one, rnd_func, rnd_param, rmu);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfGetRandom(Fp, &one, rnd_func, rnd_param, rnu);
    BREAK_ON_EPID_ERROR(sts);

    // 5.  The member computes R1 = G1.sscmMultiExp(K, rmu, B, rnu).
    sts = WriteFfElement(Fp, rmu, &rmu_str, sizeof(rmu_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, rnu, &rnu_str, sizeof(rnu_str));
    BREAK_ON_EPID_ERROR(sts);
    {
      EcPoint const* points[2];
      BigNumStr const* exponents[2];
      points[0] = K;
      points[1] = B;
      exponents[0] = &rmu_str;
      exponents[1] = &rnu_str;
      sts = EcSscmMultiExp(G1, points, exponents, COUNT_OF(points), t);
      BREAK_ON_EPID_ERROR(sts);
    }
    sts = WriteEcPoint(G1, t, &commit_out->R1, sizeof(commit_out->R1));
    BREAK_ON_EPID_ERROR(sts);

    // re-using B for B' and K for K'
    sts = ReadEcPoint(G1, &(sigrl_entry->b), sizeof(sigrl_entry->b), B);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(G1, &(sigrl_entry->k), sizeof(sigrl_entry->k), K);
    BREAK_ON_EPID_ERROR(sts);

    // 3.  The member computes T = G1.sscmMultiExp(K', mu, B', nu).
    sts = WriteFfElement(Fp, mu, &mu_str, sizeof(mu_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, nu, &nu_str, sizeof(nu_str));
    BREAK_ON_EPID_ERROR(sts);
    {
      EcPoint const* points[2];
      BigNumStr const* exponents[2];
      points[0] = K;
      points[1] = B;
      exponents[0] = &mu_str;
      exponents[1] = &nu_str;
      sts = EcSscmMultiExp(G1, points, exponents, COUNT_OF(points), t);
      BREAK_ON_EPID_ERROR(sts);
      sts = WriteEcPoint(G1, t, &commit_out->T, sizeof(commit_out->T));
      BREAK_ON_EPID_ERROR(sts);
    }

    // 6.  The member computes R2 = G1.sscmMultiExp(K', rmu, B', rnu).
    {
      EcPoint const* points[2];
      BigNumStr const* exponents[2];
      points[0] = K;
      points[1] = B;
      exponents[0] = &rmu_str;
      exponents[1] = &rnu_str;
      sts = EcSscmMultiExp(G1, points, exponents, COUNT_OF(points), t);
      BREAK_ON_EPID_ERROR(sts);
      sts = WriteEcPoint(G1, t, &commit_out->R2, sizeof(commit_out->R2));
      BREAK_ON_EPID_ERROR(sts);
    }

    ctx->secret.nrprove_pending = true;

    sts = kEpidNoErr;
  } while (0);

  EpidZeroMemory(&mu_str, sizeof(mu_str));
  EpidZeroMemory(&nu_str, sizeof(nu_str));
  EpidZeroMemory(&rmu_str, sizeof(rmu_str));
  EpidZeroMemory(&rnu_str, sizeof(rnu_str));
  DeleteEcPoint(&B);
  DeleteEcPoint(&K);
  DeleteEcPoint(&t);

  return sts;
}

EpidStatus TpmNrProve(TpmCtx* ctx, FpElemStr const* c_str, FpElemStr* smu_str,
                      FpElemStr* snu_str) {
  EpidStatus sts = kEpidErr;

  FfElement* t = NULL;  // temporary multiplication sts
  FfElement* c = NULL;

  if (!ctx || !c_str || !smu_str || !snu_str || !ctx->epid2_params) {
    return kEpidBadArgErr;
  }

  if (!ctx->secret.nrprove_pending) {
    return kEpidOutOfSequenceError;
  }

  do {
    FiniteField* Fp = ctx->epid2_params->Fp;
    FfElement const* mu = ctx->secret.mu;
    FfElement const* nu = ctx->secret.nu;
    FfElement const* rmu = ctx->secret.rmu;
    FfElement const* rnu = ctx->secret.rnu;

    sts = NewFfElement(Fp, &t);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewFfElement(Fp, &c);
    BREAK_ON_EPID_ERROR(sts);

    sts = ReadFfElement(Fp, c_str, sizeof(*c_str), c);
    BREAK_ON_EPID_ERROR(sts);

    // 8.  The member computes smu = (rmu + c * mu) mod p.
    sts = FfMul(Fp, c, mu, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfAdd(Fp, rmu, t, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, t, smu_str, sizeof(*smu_str));
    BREAK_ON_EPID_ERROR(sts);

    // 9.  The member computes snu = (rnu + c * nu) mod p.
    sts = FfMul(Fp, c, nu, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfAdd(Fp, rnu, t, t);
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, t, snu_str, sizeof(*snu_str));
    BREAK_ON_EPID_ERROR(sts);

    ctx->secret.nrprove_pending = false;

    sts = kEpidNoErr;
  } while (0);

  DeleteFfElement(&t);
  DeleteFfElement(&c);

  return sts;
}
