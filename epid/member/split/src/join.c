/*############################################################################
  # Copyright 2017-2019 Intel Corporation
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
/// Join Request related implementation.
/*! \file */
#define EXPORT_EPID_APIS
#include <epid/member/api.h>

#include "common/endian_convert.h"
#include "common/epid2params.h"
#include "common/gid_parser.h"
#include "common/grouppubkey.h"
#include "common/hashsize.h"
#include "epid/member/split/context.h"
#include "epid/member/split/join_commitment.h"
#include "epid/member/split/privateexp.h"
#include "epid/member/split/resize.h"
#include "epid/member/split/tpm2/commit.h"
#include "epid/member/split/tpm2/context.h"
#include "epid/member/split/tpm2/createprimary.h"
#include "epid/member/split/tpm2/flushcontext.h"
#include "epid/member/split/tpm2/load_external.h"
#include "epid/member/split/tpm2/sign.h"
#include "epid/types.h"
#include "ippmath/memory.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

#pragma pack(1)
/// Storage for values to a hash in Tpm2Commit
typedef struct S2CommitValues {
  OctStr32 i;    ///< Intel(R) EPID 2.0 parameter p
  G1ElemStr h1;  ///< Group public key value h1
} S2CommitValues;
#pragma pack()

size_t EPID_MEMBER_API EpidGetJoinRequestSize(void) {
  return sizeof(SplitJoinRequest);
}

EpidStatus EPID_MEMBER_API EpidCreateJoinRequest(MemberCtx* ctx,
                                                 GroupPubKey const* pub_key,
                                                 IssuerNonce const* ni,
                                                 JoinRequest* joinreq,
                                                 size_t joinreq_len) {
  EpidStatus sts = kEpidErr;
  GroupPubKey_* pub_key_ = NULL;
  EcPoint* h1 = NULL;
  EcPoint* K = NULL;
  EcPoint* l = NULL;
  EcPoint* e = NULL;

  FfElement* h1_y = NULL;
  FfElement* k = NULL;
  FfElement* s = NULL;
  uint8_t* digest = NULL;
  uint16_t counter = 0;
  bool is_counter_set = false;

  Tpm2Key* f_handle = NULL;
  SplitJoinRequest* request = NULL;

  if (!ctx || !pub_key || !ni || !joinreq || !ctx->epid2_params) {
    return kEpidBadArgErr;
  }
  if (joinreq_len >= sizeof(SplitJoinRequest)) {
    request = (SplitJoinRequest*)joinreq;
  } else {
    return kEpidNoMemErr;
  }

  do {
    G1ElemStr R = {0};
    G1ElemStr h1_str = {0};
    EcGroup* G1 = ctx->epid2_params->G1;
    FiniteField* Fp = ctx->epid2_params->Fp;
    FiniteField* Fq = ctx->epid2_params->Fq;
    size_t digest_size = 0;
    S2CommitValues commit_values;
    uint32_t iteration;
    HashAlg hash_alg = kInvalidHashAlg;

    sts = EpidParseHashAlg(&pub_key->gid, &hash_alg);
    BREAK_ON_EPID_ERROR(sts);

    sts = CreatePrivateF(ctx, hash_alg, &f_handle);
    BREAK_ON_EPID_ERROR(sts);

    // validate public key by creating
    sts = CreateGroupPubKey(pub_key, ctx->epid2_params->G1,
                            ctx->epid2_params->G2, &pub_key_);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewEcPoint(G1, &h1);
    BREAK_ON_EPID_ERROR(sts);
    sts =
        EcHash(G1, &pub_key->h1, sizeof(pub_key->h1), hash_alg, h1, &iteration);
    BREAK_ON_EPID_ERROR(sts);
    iteration = htonl(iteration);
    if (0 != memcpy_S(request->i.data, sizeof(request->i.data), &iteration,
                      sizeof(iteration))) {
      sts = kEpidBadArgErr;
      BREAK_ON_EPID_ERROR(sts);
    }
    commit_values.i = request->i;
    commit_values.h1 = pub_key->h1;
    sts = WriteEcPoint(G1, h1, &h1_str, sizeof(h1_str));
    BREAK_ON_EPID_ERROR(sts);
    request->y = h1_str.y;
    // 1. The member chooses a random integer r from [1, p-1].
    // 2. The member computes F = G1.EcExp(h1, f).
    // 3. The member computes R = G1.EcExp(h1, r).
    sts = NewFfElement(Fq, &h1_y);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &K);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &l);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(G1, &e);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(Fq, &h1_str.y, sizeof(h1_str.y), h1_y);
    BREAK_ON_EPID_ERROR(sts);
    sts = Tpm2Commit(ctx->tpm2_ctx, f_handle, NULL, &commit_values,
                     sizeof(commit_values), h1_y, K, l, e, &(counter));
    BREAK_ON_EPID_ERROR(sts);
    is_counter_set = true;
    sts = WriteEcPoint(G1, l, &R, sizeof(R));
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteEcPoint(G1, K, &request->F, sizeof(request->F));
    BREAK_ON_EPID_ERROR(sts);

    sts = HashJoinCommitment(ctx->epid2_params->Fp, hash_alg, pub_key, &h1_str,
                             &request->F, &R, ni, &request->c);
    BREAK_ON_EPID_ERROR(sts);

    // Extend value c to be of a digest size.
    digest_size = EpidGetHashSize(hash_alg);
    digest = (uint8_t*)SAFE_ALLOC(digest_size);
    if (!digest) {
      sts = kEpidMemAllocErr;
      break;
    }
    sts = ResizeOctStr(&request->c, sizeof(request->c), digest, digest_size);
    BREAK_ON_EPID_ERROR(sts);

    // Step 5. The member computes s = (r + hash(k||c) * f) mod p.
    sts = NewFfElement(Fp, &k);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(Fp, &s);
    BREAK_ON_EPID_ERROR(sts);
    sts = Tpm2Sign(ctx->tpm2_ctx, f_handle, digest, digest_size, counter, k, s);
    BREAK_ON_EPID_ERROR(sts);
    is_counter_set = false;
    sts = WriteFfElement(Fp, k, &request->k, sizeof(request->k));
    BREAK_ON_EPID_ERROR(sts);
    sts = WriteFfElement(Fp, s, &request->s, sizeof(request->s));
    BREAK_ON_EPID_ERROR(sts);

    // Step 6. The output join request is (F, c, s).
    sts = kEpidNoErr;
  } while (0);

  if (is_counter_set == true) {
    (void)Tpm2ReleaseCounter(ctx->tpm2_ctx, counter, f_handle);
  }

  Tpm2FlushContext(ctx->tpm2_ctx, &f_handle);
  DeleteEcPoint(&h1);
  DeleteEcPoint(&K);
  DeleteEcPoint(&l);
  DeleteEcPoint(&e);
  DeleteFfElement(&h1_y);
  DeleteFfElement(&k);
  DeleteFfElement(&s);
  SAFE_FREE(digest);
  DeleteGroupPubKey(&pub_key_);

  return sts;
}
