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
/// Tpm2Sign implementation.
/*! \file */

#include "epid/member/split/tpm2/sign.h"
#include <stddef.h>
#include <string.h>
#include <tss2/tss.h>
#include "epid/common/math/finitefield.h"
#include "epid/common/src/epid2params.h"
#include "epid/common/src/hashsize.h"
#include "epid/common/src/memory.h"
#include "epid/common/types.h"
#include "epid/member/split/tpm2/getrandom.h"
#include "epid/member/split/tpm2/ibm_tss/conversion.h"
#include "epid/member/split/tpm2/ibm_tss/printtss.h"
#include "epid/member/split/tpm2/ibm_tss/state.h"

/// Handle Intel(R) EPID Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

/// Bit 7 binary mask
#define BIT7 0x080
/// Binary 00011111
#define BITS0500 0x3f

EpidStatus Tpm2Sign(Tpm2Ctx* ctx, Tpm2Key const* key, void const* digest,
                    size_t digest_len, uint16_t counter, FfElement* k,
                    FfElement* s) {
  EpidStatus sts = kEpidErr;
  TPM_RC rc = TPM_RC_SUCCESS;

  if (!ctx || !ctx->epid2_params || !key || !digest || !s) {
    return kEpidBadArgErr;
  }
  if (0 == digest_len || EpidGetHashSize(key->hash_alg) != digest_len) {
    return kEpidBadArgErr;
  }
  if (key->handle == 0) {
    return kEpidBadArgErr;
  }

  do {
    TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
    unsigned int sessionAttributes0 = 0;
    Sign_In in = {0};
    Sign_Out out;
    FiniteField* Fp = ctx->epid2_params->Fp;
    FpElemStr k_str;
    FpElemStr s_str;
    in.keyHandle = key->handle;
    if (0 != memcpy_S(in.digest.t.buffer, sizeof(in.digest.t.buffer), digest,
                      digest_len)) {
      sts = kEpidErr;
      break;
    }
    in.digest.t.size = (uint16_t)digest_len;
    in.inScheme.scheme = TPM_ALG_ECDAA;
    in.inScheme.details.ecdaa.hashAlg = EpidToTpm2HashAlg(key->hash_alg);
    in.inScheme.details.ecdaa.count = counter;
    /* proof that digest was created by the TPM (NULL ticket) */
    /* Table 91 - Definition of TPMT_TK_HASHCHECK Structure */
    in.validation.tag = TPM_ST_HASHCHECK;
    in.validation.hierarchy = TPM_RH_NULL;
    in.validation.digest.t.size = 0;
    rc =
        TSS_Execute(ctx->tss, (RESPONSE_PARAMETERS*)&out,
                    (COMMAND_PARAMETERS*)&in, NULL, TPM_CC_Sign, sessionHandle0,
                    NULL, sessionAttributes0, TPM_RH_NULL, NULL, 0);
    if (rc != TPM_RC_SUCCESS) {
      print_tpm2_response_code("TPM2_Sign", rc);
      // workaround based on Table 2:15 to filter response code format defining
      // handle, session, or parameter number modifier if bit 7 is 1 error is
      // RC_FMT1
      if ((rc & BIT7) != 0) {
        rc = rc & (BITS0500 | RC_FMT1);
        if (TPM_RC_VALUE == rc) {
          sts = kEpidBadArgErr;
        }
      } else {
        sts = kEpidErr;
      }
      break;
    }

    if (k) {
      sts = WriteTpm2FfElement(&out.signature.signature.ecdaa.signatureR,
                               (OctStr256*)&k_str);
      BREAK_ON_EPID_ERROR(sts);
      sts = ReadFfElement(Fp, &k_str, sizeof(k_str), k);
      BREAK_ON_EPID_ERROR(sts);
    }

    sts = WriteTpm2FfElement(&out.signature.signature.ecdaa.signatureS,
                             (OctStr256*)&s_str);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(Fp, &s_str, sizeof(s_str), s);
    BREAK_ON_EPID_ERROR(sts);
  } while (0);
  return sts;
}

EpidStatus Tpm2ReleaseCounter(Tpm2Ctx* ctx, uint16_t counter,
                              Tpm2Key const* key) {
  EpidStatus sts = kEpidErr;

  if (!ctx || !key) {
    return kEpidBadArgErr;
  }

  do {
    TPM_RC rc = TPM_RC_SUCCESS;
    TPMI_SH_AUTH_SESSION sessionHandle0 = TPM_RS_PW;
    unsigned int sessionAttributes0 = 0;
    Sign_In in = {0};
    Sign_Out out;
    in.keyHandle = key->handle;

    in.digest.t.size = (uint16_t)EpidGetHashSize(key->hash_alg);
    memset(in.digest.t.buffer, 0x1, (size_t)in.digest.t.size);
    in.inScheme.scheme = TPM_ALG_ECDAA;
    in.inScheme.details.ecdaa.hashAlg = EpidToTpm2HashAlg(key->hash_alg);
    in.inScheme.details.ecdaa.count = counter;
    in.validation.tag = TPM_ST_HASHCHECK;
    in.validation.hierarchy = TPM_RH_NULL;
    in.validation.digest.t.size = 0;
    rc =
        TSS_Execute(ctx->tss, (RESPONSE_PARAMETERS*)&out,
                    (COMMAND_PARAMETERS*)&in, NULL, TPM_CC_Sign, sessionHandle0,
                    NULL, sessionAttributes0, TPM_RH_NULL, NULL, 0);
    if (rc != TPM_RC_SUCCESS && (rc & (BITS0500 | RC_FMT1)) != TPM_RC_VALUE) {
      print_tpm2_response_code("Tpm2ReleaseCounter: TPM2_Sign", rc);
      sts = kEpidErr;
      break;
    }
    sts = kEpidNoErr;
  } while (0);

  return sts;
}
