/*############################################################################
  # Copyright 2016-2017 Intel Corporation
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
//     Intel(R) Performance Primitives. Cryptography Primitives.
//     GF(p) methods
//
*/
#include "owndefs.h"
#include "owncp.h"

#include "pcpgfpmethod.h"
#include "pcpgfpstuff.h"



static BNU_CHUNK_T* arbp_add(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGF)
{
   /* get temporary from top of GF pool */
   BNU_CHUNK_T* pTmpR = GFP_POOL(pGF);

   BNU_CHUNK_T* pModulus = GFP_MODULUS(pGF);
   cpSize elemLen = GFP_FELEN(pGF);

   BNU_CHUNK_T e = cpAdd_BNU(pR, pA, pB, elemLen);
   e -= cpSub_BNU(pTmpR, pR, pModulus, elemLen);
   MASKED_COPY_BNU(pR, e, pR, pTmpR, elemLen);
   return pR;
}

static BNU_CHUNK_T* arbp_sub(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGF)
{
   /* get temporary from top of GF pool */
   BNU_CHUNK_T* pTmpR = GFP_POOL(pGF);

   BNU_CHUNK_T* pModulus = GFP_MODULUS(pGF);
   cpSize elemLen = GFP_FELEN(pGF);

   BNU_CHUNK_T e = cpSub_BNU(pR, pA, pB, elemLen);
   cpAdd_BNU(pTmpR, pR, pModulus, elemLen);
   MASKED_COPY_BNU(pR, (0-e), pTmpR, pR, elemLen);
   return pR;
}

static BNU_CHUNK_T* arbp_neg(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF)
{
   /* get temporary from top of GF pool */
   BNU_CHUNK_T* pTmpR = GFP_POOL(pGF);

   BNU_CHUNK_T* pModulus = GFP_MODULUS(pGF);
   cpSize elemLen = GFP_FELEN(pGF);

   BNU_CHUNK_T e = cpSub_BNU(pR, pModulus, pA, elemLen);
   e -= cpSub_BNU(pTmpR, pR, pModulus, elemLen);
   MASKED_COPY_BNU(pR, e, pR, pTmpR, elemLen);
   return pR;
}

static BNU_CHUNK_T* arbp_div_by_2(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF)
{
   BNU_CHUNK_T* pModulus = GFP_MODULUS(pGF);
   cpSize elemLen = GFP_FELEN(pGF);

   /* t = if(isOdd(A))? modulus : 0 */
   BNU_CHUNK_T mask = 0 - (pA[0]&1);
   /* get temporary from top of GF pool */
   BNU_CHUNK_T* t = GFP_POOL(pGF);
   cpSize i;
   for(i=0; i<elemLen; i++) t[i] = pModulus[i] & mask;

   t[elemLen] = cpAdd_BNU(t, t, pA, elemLen);
   cpLSR_BNU(t, t, elemLen+1, 1);
   cpGFpElementCopy(pR, t, elemLen);
   return pR;
}

static BNU_CHUNK_T* arbp_mul_by_2(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF)
{
   return arbp_add(pR, pA, pA, pGF);
}

static BNU_CHUNK_T* arbp_mul_by_3(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF)
{
   BNU_CHUNK_T* pTmpR = cpGFpGetPool(1, pGF);

   arbp_add(pTmpR, pA, pA, pGF);
   arbp_add(pR, pTmpR, pA, pGF);

   cpGFpReleasePool(1, pGF);
   return pR;
}

static BNU_CHUNK_T* arbp_mul_montl(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGF)
{
   BNU_CHUNK_T* pModulus = GFP_MODULUS(pGF);
   cpSize elemLen = GFP_FELEN(pGF);

   IppsMontState* pMont = GFP_MONT(pGF);
   BNU_CHUNK_T  m0 = MNT_HELPER(pMont);

   /* get temporary from top of GF pool */
   BNU_CHUNK_T* pBuffer = GFP_POOL(pGF);
   cpMontMul_BNU(pR, pA,elemLen, pB,elemLen, pModulus,elemLen, m0, pBuffer, NULL);
   return pR;
}

static BNU_CHUNK_T* arbp_sqr_montl(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF)
{
   BNU_CHUNK_T* pModulus = GFP_MODULUS(pGF);
   cpSize elemLen = GFP_FELEN(pGF);

   IppsMontState* pMont = GFP_MONT(pGF);
   BNU_CHUNK_T  m0 = MNT_HELPER(pMont);

   /* get temporary from top of GF pool */
   BNU_CHUNK_T* pBuffer = GFP_POOL(pGF);
   cpMontSqr_BNU(pR, pA,elemLen, pModulus,elemLen, m0, pBuffer, NULL);
   return pR;
}

static BNU_CHUNK_T* arbp_to_mont(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF)
{
   cpMontEnc_BNU(pR, pA, GFP_FELEN(pGF), GFP_MONT(pGF));
   return pR;
}

static BNU_CHUNK_T* arbp_mont_back(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGF)
{
   cpMontDec_BNU(pR, pA, GFP_FELEN(pGF), GFP_MONT(pGF));
   return pR;
}

/*
// returns methods
*/
IPPFUN( const IppsGFpMethod*, ippsGFpMethod_pArb, (void) )
{
   static IppsGFpMethod method = {
      arbp_add,
      arbp_sub,
      arbp_neg,
      arbp_div_by_2,
      arbp_mul_by_2,
      arbp_mul_by_3,
      arbp_mul_montl,
      arbp_sqr_montl,
      arbp_to_mont,
      arbp_mont_back
   };
   return &method;
}
