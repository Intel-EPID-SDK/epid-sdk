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
//     GF(p^d) methods
//
*/
#include "owndefs.h"
#include "owncp.h"

#include "pcpgfpxstuff.h"

BNU_CHUNK_T* cpGFpxAdd_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGFpx)
{
   IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);
   int basicElemLen = GFP_FELEN(pBasicGF);
   int basicDeg = cpGFpBasicDegreeExtension(pGFpx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      pBasicGF->add(pTmp, pA, pB, pBasicGF);
      pTmp += basicElemLen;
      pA += basicElemLen;
      pB += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxSub_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGFpx)
{
   IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);
   int basicElemLen = GFP_FELEN(pBasicGF);
   int basicDeg = cpGFpBasicDegreeExtension(pGFpx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      pBasicGF->sub(pTmp, pA, pB, pBasicGF);
      pTmp += basicElemLen;
      pA += basicElemLen;
      pB += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxNeg_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);
   int basicElemLen = GFP_FELEN(pBasicGF);
   int basicDeg = cpGFpBasicDegreeExtension(pGFpx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      pBasicGF->neg(pTmp, pA, pBasicGF);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxMul_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGFpx)
{
   int extDegree = GFP_DEGREE(pGFpx);

    BNU_CHUNK_T* pGFpolynomial = GFP_MODULUS(pGFpx);
    int degR = extDegree-1;
    int elemLen= GFP_FELEN(pGFpx);

    int degB = degR;
    BNU_CHUNK_T* pTmpProduct = cpGFpGetPool(2, pGFpx);
    BNU_CHUNK_T* pTmpResult = pTmpProduct + GFP_PELEN(pGFpx);

    IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
    BNU_CHUNK_T* r = cpGFpGetPool(1, pGroundGF);
    int groundElemLen = GFP_FELEN(pGroundGF);

    const BNU_CHUNK_T* pTmpB = GFPX_IDX_ELEMENT(pB, degB, groundElemLen);

    /* clear temporary */
    cpGFpElementPadd(pTmpProduct, elemLen, 0);

    /* R = A * B[degB-1] */
    cpGFpxMul_GFE(pTmpResult, pA, pTmpB, pGFpx);

    for(degB-=1; degB>=0; degB--) {
      /* save R[degR-1] */
      cpGFpElementCopy(r, GFPX_IDX_ELEMENT(pTmpResult, degR, groundElemLen), groundElemLen);

      { /* R = R * x */
         int j;
         for (j=degR; j>=1; j--)
            cpGFpElementCopy(GFPX_IDX_ELEMENT(pTmpResult, j, groundElemLen), GFPX_IDX_ELEMENT(pTmpResult, j-1, groundElemLen), groundElemLen);
         cpGFpElementPadd(pTmpResult, groundElemLen, 0);
      }

      cpGFpxMul_GFE(pTmpProduct, pGFpolynomial, r, pGFpx);
      pGFpx->sub(pTmpResult, pTmpResult, pTmpProduct, pGFpx);

      /* B[degB-i] */
      pTmpB -= groundElemLen;
      cpGFpxMul_GFE(pTmpProduct, pA, pTmpB, pGFpx);
      pGFpx->add(pTmpResult, pTmpResult, pTmpProduct, pGFpx);
   }

   /* copy result */
   cpGFpElementCopy(pR, pTmpResult, elemLen);

   /* release pools */
   cpGFpReleasePool(1, pGroundGF);
   cpGFpReleasePool(2, pGFpx);

   return pR;
}

BNU_CHUNK_T* cpGFpxSqr_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   int extDegree = GFP_DEGREE(pGFpx);

   BNU_CHUNK_T* pGFpolynomial = GFP_MODULUS(pGFpx);
   int degR = extDegree-1;
   int elemLen= GFP_FELEN(pGFpx);

   int degA = degR;
   BNU_CHUNK_T* pTmpProduct = cpGFpGetPool(2, pGFpx);
   BNU_CHUNK_T* pTmpResult = pTmpProduct + GFP_PELEN(pGFpx);

   IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
   BNU_CHUNK_T* r = cpGFpGetPool(1, pGroundGF);
   int groundElemLen = GFP_FELEN(pGroundGF);

   const BNU_CHUNK_T* pTmpA = GFPX_IDX_ELEMENT(pA, degA, groundElemLen);

   /* clear temporary */
   cpGFpElementPadd(pTmpProduct, elemLen, 0);

   /* R = A * A[degA-1] */
   cpGFpxMul_GFE(pTmpResult, pA, pTmpA, pGFpx);

   for(degA-=1; degA>=0; degA--) {
      /* save R[degR-1] */
      cpGFpElementCopy(r, GFPX_IDX_ELEMENT(pTmpResult, degR, groundElemLen), groundElemLen);

      { /* R = R * x */
         int j;
         for (j=degR; j>=1; j--)
            cpGFpElementCopy(GFPX_IDX_ELEMENT(pTmpResult, j, groundElemLen), GFPX_IDX_ELEMENT(pTmpResult, j-1, groundElemLen), groundElemLen);
         cpGFpElementPadd(pTmpResult, groundElemLen, 0);
      }

      cpGFpxMul_GFE(pTmpProduct, pGFpolynomial, r, pGFpx);
      pGFpx->sub(pTmpResult, pTmpResult, pTmpProduct, pGFpx);

      /* A[degA-i] */
      pTmpA -= groundElemLen;
      cpGFpxMul_GFE(pTmpProduct, pA, pTmpA, pGFpx);
      pGFpx->add(pTmpResult, pTmpResult, pTmpProduct, pGFpx);
   }

   /* copy result */
   cpGFpElementCopy(pR, pTmpResult, elemLen);

   /* release pools */
   cpGFpReleasePool(1, pGroundGF);
   cpGFpReleasePool(2, pGFpx);

   return pR;
}

BNU_CHUNK_T* cpGFpxDiv2_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);
   int basicElemLen = GFP_FELEN(pBasicGF);
   int basicDeg = cpGFpBasicDegreeExtension(pGFpx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      pBasicGF->div2(pTmp, pA, pBasicGF);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxMul2_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);
   int basicElemLen = GFP_FELEN(pBasicGF);
   int basicDeg = cpGFpBasicDegreeExtension(pGFpx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      pBasicGF->mul2(pTmp, pA, pBasicGF);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxMul3_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);
   int basicElemLen = GFP_FELEN(pBasicGF);
   int basicDeg = cpGFpBasicDegreeExtension(pGFpx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      pBasicGF->mul3(pTmp, pA, pBasicGF);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxEncode_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);
   int basicElemLen = GFP_FELEN(pBasicGF);
   int basicDeg = cpGFpBasicDegreeExtension(pGFpx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      pBasicGF->encode(pTmp, pA, pBasicGF);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxDecode_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);
   int basicElemLen = GFP_FELEN(pBasicGF);
   int basicDeg = cpGFpBasicDegreeExtension(pGFpx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      pBasicGF->decode(pTmp, pA, pBasicGF);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

/*
// returns methods
*/
IPPFUN( const IppsGFpMethod*, ippsGFpxMethod_com, (void) )
{
   static IppsGFpMethod method = {
      cpGFpxAdd_com,
      cpGFpxSub_com,
      cpGFpxNeg_com,
      cpGFpxDiv2_com,
      cpGFpxMul2_com,
      cpGFpxMul3_com,
      cpGFpxMul_com,
      cpGFpxSqr_com,
      cpGFpxEncode_com,
      cpGFpxDecode_com
   };
   return &method;
}

