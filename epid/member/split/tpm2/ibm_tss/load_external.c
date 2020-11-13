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
/// TPM2_LoadExternal command implementation.
/*! \file */

#include "epid/member/split/tpm2/load_external.h"

#include "common/epid2params.h"
#include "epid/member/split/tpm2/flushcontext.h"
#include "epid/member/split/tpm2/ibm_tss/conversion.h"
#include "epid/member/split/tpm2/ibm_tss/printtss.h"
#include "epid/member/split/tpm2/ibm_tss/registerkey.h"
#include "epid/member/split/tpm2/ibm_tss/state.h"
#include "ippmath/ecgroup.h"
#include "ippmath/memory.h"
#include "tss2/TPM_Types.h"
#include "tss2/tss.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus Tpm2LoadExternal(Tpm2Ctx* ctx, HashAlg hash_alg,
                            FpElemStr const* f_str, Tpm2Key** key) {
  EpidStatus sts = kEpidErr;
  Tpm2Key* new_key = NULL;
  EcPoint* pub = NULL;
  FfElement* f = NULL;

  if (!ctx || !ctx->epid2_params || !f_str || !key) {
    return kEpidBadArgErr;
  }

  new_key = SAFE_ALLOC(sizeof(Tpm2Key));
  if (!new_key) {
    return kEpidMemAllocErr;
  }
  sts = Tpm2RegisterKey(ctx, new_key);
  if (kEpidNoErr != sts) {
    SAFE_FREE(new_key);
    return sts;
  }

  do {
    TPM_RC rc = TPM_RC_SUCCESS;
    TPMI_ALG_HASH tpm_hash_alg = TPM_ALG_NULL;
    LoadExternal_In in = {0};
    LoadExternal_Out out;
    G1ElemStr pub_str = {0};
    TPMS_ECC_PARMS* ecc_details = &in.inPublic.publicArea.parameters.eccDetail;
    EcGroup* G1 = ctx->epid2_params->G1;
    EcPoint* g1 = ctx->epid2_params->g1;

    sts = NewFfElement(ctx->epid2_params->Fp, &f);
    BREAK_ON_EPID_ERROR(sts);
    // verify that f is valid
    sts = ReadFfElement(ctx->epid2_params->Fp, f_str, sizeof(*f_str), f);
    BREAK_ON_EPID_ERROR(sts);

    sts = NewEcPoint(G1, &pub);
    BREAK_ON_EPID_ERROR(sts);

    sts = EcExp(G1, g1, (BigNumStr const*)f_str, pub);
    BREAK_ON_EPID_ERROR(sts);

    sts = WriteEcPoint(G1, pub, &pub_str, sizeof(pub_str));
    BREAK_ON_EPID_ERROR(sts);

    tpm_hash_alg = EpidToTpm2HashAlg(hash_alg);
    if (tpm_hash_alg == TPM_ALG_NULL) {
      sts = kEpidHashAlgorithmNotSupported;
      break;
    }

    in.hierarchy = TPM_RH_NULL;
    in.inPublic.size = sizeof(TPM2B_PUBLIC);
    in.inPublic.publicArea.type = TPM_ALG_ECC;
    in.inPublic.publicArea.nameAlg = tpm_hash_alg;
    in.inPublic.publicArea.objectAttributes.val =
        TPMA_OBJECT_NODA | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN;
    in.inPublic.publicArea.authPolicy.t.size = 0;

    ecc_details->symmetric.algorithm = TPM_ALG_NULL;
    ecc_details->scheme.scheme = TPM_ALG_ECDAA;
    ecc_details->scheme.details.ecdaa.hashAlg = tpm_hash_alg;
    ecc_details->scheme.details.ecdaa.count = 0;
    ecc_details->curveID = TPM_ECC_BN_P256;
    ecc_details->kdf.scheme = TPM_ALG_NULL;

    sts = ReadTpm2FfElement(&pub_str.x.data,
                            &in.inPublic.publicArea.unique.ecc.x);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadTpm2FfElement(&pub_str.y.data,
                            &in.inPublic.publicArea.unique.ecc.y);
    BREAK_ON_EPID_ERROR(sts);

    in.inPrivate.t.size = sizeof(in.inPrivate.t.sensitiveArea);
    in.inPrivate.t.sensitiveArea.sensitiveType = TPM_ALG_ECC;
    sts = ReadTpm2FfElement(&f_str->data,
                            &in.inPrivate.t.sensitiveArea.sensitive.ecc);
    BREAK_ON_EPID_ERROR(sts);

    rc = TSS_Execute(ctx->tss, (RESPONSE_PARAMETERS*)&out,
                     (COMMAND_PARAMETERS*)&in, NULL, TPM_CC_LoadExternal,
                     TPM_RH_NULL, NULL, 0);
    new_key->handle = out.objectHandle;
    if (rc != TPM_RC_SUCCESS) {
      print_tpm2_response_code("TPM2_LoadExternal", rc);
      if (TPM_RC_BINDING == rc || TPM_RC_ECC_POINT == rc ||
          TPM_RC_KEY_SIZE == rc)
        sts = kEpidBadArgErr;
      else
        sts = kEpidErr;
      break;
    }

    new_key->hash_alg = hash_alg;

    sts = kEpidNoErr;
  } while (0);

  DeleteEcPoint(&pub);
  DeleteFfElement(&f);

  if (kEpidNoErr != sts) {
    Tpm2FlushContext(ctx, &new_key);
  } else {
    *key = new_key;
  }

  return sts;
}
