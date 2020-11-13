/*############################################################################
# Copyright 2019 Intel Corporation
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
/// Validate Private Key implementation
/*! \file */

#include "common/validate_privkey.h"

#include "common/epid2params.h"
#include "common/gid_parser.h"
#include "epid/types.h"
#include "ippmath/ecgroup.h"
#include "ippmath/finitefield.h"
#include "ippmath/memory.h"
#include "ippmath/pairing.h"

/// Handle SDK Error with Break
#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

EpidStatus EpidValidateNonSplitPrivateKey(PrivKey const* priv_key,
                                          GroupPubKey const* pub_key) {
  EpidStatus sts = kEpidNoErr;
  Epid2Params_* epid_params = NULL;
  EcPoint* t1 = NULL;
  EcPoint* t2 = NULL;
  FfElement* t3 = NULL;
  FfElement* t4 = NULL;
  EcPoint* A = NULL;
  EcPoint* h1 = NULL;
  EcPoint* h2 = NULL;
  EcPoint* w = NULL;
  FfElement* x = NULL;
  FfElement* f_fp = NULL;
  bool is_valid = false;
  HashAlg hash_alg = kInvalidHashAlg;
  if (!priv_key) {
    return kEpidBadPrivKeyErr;
  }
  if (!pub_key) {
    return kEpidBadGroupPubKeyErr;
  }
  sts = EpidParseHashAlg(&priv_key->gid, &hash_alg);
  if (kEpidNoErr != sts) {
    return kEpidBadPrivKeyErr;
  }
  sts = EpidParseHashAlg(&pub_key->gid, &hash_alg);
  if (kEpidNoErr != sts) {
    return kEpidBadGroupPubKeyErr;
  }
  if (memcmp(&pub_key->gid, &priv_key->gid, sizeof(GroupId))) {
    return kEpidKeyNotInGroupErr;
  }
  do {
    sts = CreateEpid2Params(&epid_params);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(epid_params->Fp, &x);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(epid_params->Fp, &priv_key->x, sizeof(priv_key->x), x);
    if (kEpidNoErr != sts) {
      sts = kEpidBadPrivKeyErr;
      break;
    }
    // 2. The member computes t1 = G2.sscmExp(g2, x).
    sts = NewEcPoint(epid_params->G2, &t1);
    BREAK_ON_EPID_ERROR(sts);

    sts = EcSscmExp(epid_params->G2, epid_params->g2,
                    (BigNumStr const*)&priv_key->x, t1);
    BREAK_ON_EPID_ERROR(sts);
    // 3. The member computes t1 = G2.mul(t1, w).
    sts = NewEcPoint(epid_params->G2, &w);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(epid_params->G2, &pub_key->w, sizeof(pub_key->w), w);
    if (kEpidNoErr != sts) {
      sts = kEpidBadGroupPubKeyErr;
      break;
    }
    sts = EcMul(epid_params->G2, t1, w, t1);
    BREAK_ON_EPID_ERROR(sts);
    // 4. The member computes t3 = pairing(A, t1).
    sts = NewFfElement(epid_params->GT, &t3);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(epid_params->G1, &A);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(epid_params->G1, &priv_key->A, sizeof(priv_key->A), A);
    if (kEpidNoErr != sts) {
      sts = kEpidBadPrivKeyErr;
      break;
    }
    sts = Pairing(epid_params->pairing_state, A, t1, t3);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(epid_params->G1, &t2);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(epid_params->G1, &h2);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(epid_params->Fp, &f_fp);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(epid_params->G1, &pub_key->h2, sizeof(pub_key->h2), h2);
    if (kEpidNoErr != sts) {
      sts = kEpidBadGroupPubKeyErr;
      break;
    }
    sts =
        ReadFfElement(epid_params->Fp, &priv_key->f, sizeof(priv_key->f), f_fp);
    if (kEpidNoErr != sts) {
      sts = kEpidBadPrivKeyErr;
      break;
    }
    // 5. The member computes t2 = G1.sscmExp(h1, f).
    sts = NewEcPoint(epid_params->G1, &h1);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(epid_params->G1, &pub_key->h1, sizeof(pub_key->h1), h1);
    if (kEpidNoErr != sts) {
      sts = kEpidBadGroupPubKeyErr;
      break;
    }
    sts = EcExp(epid_params->G1, h1, (BigNumStr const*)&priv_key->f, t2);
    BREAK_ON_EPID_ERROR(sts);
    // 6. The member computes t2 = G1.mul(t2, g1).
    sts = EcMul(epid_params->G1, t2, epid_params->g1, t2);
    BREAK_ON_EPID_ERROR(sts);

    // 7. The member computes t4 = pairing(t2, g2).
    sts = NewFfElement(epid_params->GT, &t4);
    BREAK_ON_EPID_ERROR(sts);
    sts = Pairing(epid_params->pairing_state, t2, epid_params->g2, t4);
    BREAK_ON_EPID_ERROR(sts);

    // 8. If GT.isEqual(t3, t4) = false, reports bad private key.
    sts = FfIsEqual(epid_params->GT, t3, t4, &is_valid);
    if (kEpidNoErr != sts) {
      BREAK_ON_EPID_ERROR(sts);
    }
    if (!is_valid) {
      sts = kEpidKeyNotInGroupErr;
      BREAK_ON_EPID_ERROR(sts);
    }
  } while (0);
  DeleteEpid2Params(&epid_params);
  DeleteEcPoint(&t1);
  DeleteEcPoint(&t2);
  DeleteFfElement(&t3);
  DeleteFfElement(&t4);
  DeleteEcPoint(&A);
  DeleteFfElement(&x);
  DeleteEcPoint(&h1);
  DeleteEcPoint(&h2);
  DeleteEcPoint(&w);
  DeleteFfElement(&f_fp);
  return sts;
}

EpidStatus EpidValidateSplitPrivateKey(PrivKey const* priv_key,
                                       GroupPubKey const* pub_key) {
  EpidStatus sts = kEpidNoErr;
  Epid2Params_* epid_params = NULL;
  EcPoint* t1 = NULL;
  EcPoint* t2 = NULL;
  FfElement* t3 = NULL;
  FfElement* t4 = NULL;
  EcPoint* A = NULL;
  EcPoint* h1 = NULL;
  EcPoint* h2 = NULL;
  EcPoint* w = NULL;
  EcPoint* e = NULL;
  FfElement* x = NULL;
  FfElement* r = NULL;
  FfElement* s = NULL;
  FfElement* f_fp = NULL;
  bool is_valid = false;
  HashAlg hash_alg = kInvalidHashAlg;
  if (!priv_key) {
    return kEpidBadPrivKeyErr;
  }
  if (!pub_key) {
    return kEpidBadGroupPubKeyErr;
  }
  sts = EpidParseHashAlg(&priv_key->gid, &hash_alg);
  if (kEpidNoErr != sts) {
    return kEpidBadPrivKeyErr;
  }
  sts = EpidParseHashAlg(&pub_key->gid, &hash_alg);
  if (kEpidNoErr != sts) {
    return kEpidBadGroupPubKeyErr;
  }
  if (memcmp(&pub_key->gid, &priv_key->gid, sizeof(GroupId))) {
    return kEpidKeyNotInGroupErr;
  }
  do {
    const FpElemStr r_str = {1};
    BigNumStr tmp_ff_str = {0};
    sts = CreateEpid2Params(&epid_params);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(epid_params->Fp, &x);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(epid_params->Fp, &priv_key->x, sizeof(priv_key->x), x);
    if (kEpidNoErr != sts) {
      sts = kEpidBadPrivKeyErr;
      break;
    }
    // 2. The member computes t1 = G2.sscmExp(g2, x).
    sts = NewEcPoint(epid_params->G2, &t1);
    BREAK_ON_EPID_ERROR(sts);

    sts = EcSscmExp(epid_params->G2, epid_params->g2,
                    (BigNumStr const*)&priv_key->x, t1);
    BREAK_ON_EPID_ERROR(sts);
    // 3. The member computes t1 = G2.mul(t1, w).
    sts = NewEcPoint(epid_params->G2, &w);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(epid_params->G2, &pub_key->w, sizeof(pub_key->w), w);
    if (kEpidNoErr != sts) {
      sts = kEpidBadGroupPubKeyErr;
      break;
    }
    sts = EcMul(epid_params->G2, t1, w, t1);
    BREAK_ON_EPID_ERROR(sts);
    // 4. The member computes t3 = pairing(A, t1).
    sts = NewFfElement(epid_params->GT, &t3);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(epid_params->G1, &A);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(epid_params->G1, &priv_key->A, sizeof(priv_key->A), A);
    if (kEpidNoErr != sts) {
      sts = kEpidBadPrivKeyErr;
      break;
    }
    sts = Pairing(epid_params->pairing_state, A, t1, t3);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(epid_params->Fp, &r);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(epid_params->Fp, &s);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewFfElement(epid_params->Fp, &f_fp);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(epid_params->G1, &t2);
    BREAK_ON_EPID_ERROR(sts);
    sts = NewEcPoint(epid_params->G1, &h2);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(epid_params->G1, &pub_key->h2, sizeof(pub_key->h2), h2);
    if (kEpidNoErr != sts) {
      sts = kEpidBadGroupPubKeyErr;
      break;
    }
    sts = NewEcPoint(epid_params->G1, &h1);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadEcPoint(epid_params->G1, &pub_key->h1, sizeof(pub_key->h1), h1);
    if (kEpidNoErr != sts) {
      sts = kEpidBadGroupPubKeyErr;
      break;
    }
    // 5. The member computes h1 = G1.Hash(h1).
    sts = EcHash(epid_params->G1, &pub_key->h1, sizeof(pub_key->h1), hash_alg,
                 h1, NULL);
    BREAK_ON_EPID_ERROR(sts);
    // 6. The member computes t2 = G1.sscmExp(h1, 1).
    sts = NewEcPoint(epid_params->G1, &e);
    BREAK_ON_EPID_ERROR(sts);
    sts = EcExp(epid_params->G1, h1, (BigNumStr const*)&r_str, e);
    BREAK_ON_EPID_ERROR(sts);
    sts =
        ReadFfElement(epid_params->Fp, &priv_key->f, sizeof(priv_key->f), f_fp);
    if (kEpidNoErr != sts) {
      sts = kEpidBadPrivKeyErr;
      break;
    }
    // 7. compute integer s = (x + T*f)(mod p)
    sts = FfMul(epid_params->Fp, f_fp, x, s);
    BREAK_ON_EPID_ERROR(sts);
    sts = ReadFfElement(epid_params->Fp, &r_str, sizeof(r_str), r);
    BREAK_ON_EPID_ERROR(sts);
    sts = FfAdd(epid_params->Fp, r, s, s);
    BREAK_ON_EPID_ERROR(sts);
    // 8. k1 = Fq.inv(k1)
    sts = FfInv(epid_params->Fp, x, x);
    BREAK_ON_EPID_ERROR(sts);
    // 9. t1 = G1.sscmExp(B', s)
    sts = WriteFfElement(epid_params->Fp, s, &tmp_ff_str, sizeof(tmp_ff_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = EcSscmExp(epid_params->G1, h1, &tmp_ff_str, t2);
    BREAK_ON_EPID_ERROR(sts);

    // 10. E_PT = G1.inv(E_PT)
    sts = EcInverse(epid_params->G1, e, e);
    BREAK_ON_EPID_ERROR(sts);

    // 11. h = G1.mul(t1, E_PT)
    sts = EcMul(epid_params->G1, t2, e, h1);
    BREAK_ON_EPID_ERROR(sts);

    // 12. h = G1.sscmExp(h, k1)
    sts = WriteFfElement(epid_params->Fp, x, &tmp_ff_str, sizeof(tmp_ff_str));
    BREAK_ON_EPID_ERROR(sts);
    sts = EcSscmExp(epid_params->G1, h1, &tmp_ff_str, t2);
    BREAK_ON_EPID_ERROR(sts);

    // 13. The member computes t2 = G1.mul(t2, g1).
    sts = EcMul(epid_params->G1, t2, epid_params->g1, t2);
    BREAK_ON_EPID_ERROR(sts);

    // 14. The member computes t4 = pairing(t2, g2).
    sts = NewFfElement(epid_params->GT, &t4);
    BREAK_ON_EPID_ERROR(sts);
    sts = Pairing(epid_params->pairing_state, t2, epid_params->g2, t4);
    BREAK_ON_EPID_ERROR(sts);

    // 15. If GT.isEqual(t3, t4) = false, reports bad private key.
    sts = FfIsEqual(epid_params->GT, t3, t4, &is_valid);
    if (kEpidNoErr != sts) {
      BREAK_ON_EPID_ERROR(sts);
    }
    if (!is_valid) {
      sts = kEpidKeyNotInGroupErr;
      BREAK_ON_EPID_ERROR(sts);
    }
  } while (0);
  DeleteEpid2Params(&epid_params);
  DeleteEcPoint(&t1);
  DeleteEcPoint(&t2);
  DeleteFfElement(&t3);
  DeleteFfElement(&t4);
  DeleteEcPoint(&A);
  DeleteFfElement(&f_fp);
  DeleteFfElement(&x);
  DeleteEcPoint(&h1);
  DeleteEcPoint(&h2);
  DeleteEcPoint(&w);
  DeleteEcPoint(&e);
  DeleteFfElement(&r);
  DeleteFfElement(&s);
  return sts;
}

EpidStatus EpidValidatePrivateKey(PrivKey const* priv_key,
                                  GroupPubKey const* pub_key) {
  EpidStatus sts = kEpidNoErr;
  sts = EpidValidateNonSplitPrivateKey(priv_key, pub_key);
  if (kEpidKeyNotInGroupErr == sts) {
    sts = EpidValidateSplitPrivateKey(priv_key, pub_key);
  }
  return sts;
}
