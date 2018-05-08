/*############################################################################
  # Copyright 1999-2018 Intel Corporation
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
#include "owncp.h"

#include "pcpgfpxstuff.h"

//gres: temporary excluded: #include <assert.h>


BNU_CHUNK_T* cpGFpxAdd_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, gsEngine* pGFEx)
{
   gsEngine* pBasicGFE = cpGFpBasic(pGFEx);
   mod_add addF = GFP_METHOD(pBasicGFE)->add;
   int basicElemLen = GFP_FELEN(pBasicGFE);
   int basicDeg = cpGFpBasicDegreeExtension(pGFEx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      addF(pTmp, pA, pB, pBasicGFE);
      pTmp += basicElemLen;
      pA += basicElemLen;
      pB += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxSub_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, gsEngine* pGFEx)
{
   gsEngine* pBasicGFE = cpGFpBasic(pGFEx);
   mod_sub subF = GFP_METHOD(pBasicGFE)->sub;
   int basicElemLen = GFP_FELEN(pBasicGFE);
   int basicDeg = cpGFpBasicDegreeExtension(pGFEx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      subF(pTmp, pA, pB, pBasicGFE);
      pTmp += basicElemLen;
      pA += basicElemLen;
      pB += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxNeg_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsEngine* pGFEx)
{
   gsEngine* pBasicGFE = cpGFpBasic(pGFEx);
   mod_neg negF = GFP_METHOD(pBasicGFE)->neg;
   int basicElemLen = GFP_FELEN(pBasicGFE);
   int basicDeg = cpGFpBasicDegreeExtension(pGFEx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      negF(pTmp, pA, pBasicGFE);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxMul_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, gsEngine* pGFEx)
{
   int extDegree = GFP_EXTDEGREE(pGFEx);

    BNU_CHUNK_T* pGFpolynomial = GFP_MODULUS(pGFEx);
    int degR = extDegree-1;
    int elemLen= GFP_FELEN(pGFEx);

    int degB = degR;
    BNU_CHUNK_T* pTmpProduct = cpGFpGetPool(2, pGFEx);
    BNU_CHUNK_T* pTmpResult = pTmpProduct + GFP_PELEN(pGFEx);

    gsEngine* pGroundGFE = GFP_PARENT(pGFEx);
    BNU_CHUNK_T* r = cpGFpGetPool(1, pGroundGFE);
    int groundElemLen = GFP_FELEN(pGroundGFE);

    const BNU_CHUNK_T* pTmpB = GFPX_IDX_ELEMENT(pB, degB, groundElemLen);

    //gres: temporary excluded: assert(NULL!=pTmpProduct && NULL!=r);

    /* clear temporary */
    cpGFpElementPadd(pTmpProduct, elemLen, 0);

    /* R = A * B[degB-1] */
    cpGFpxMul_GFE(pTmpResult, pA, pTmpB, pGFEx);

    for(degB-=1; degB>=0; degB--) {
      /* save R[degR-1] */
      cpGFpElementCopy(r, GFPX_IDX_ELEMENT(pTmpResult, degR, groundElemLen), groundElemLen);

      { /* R = R * x */
         int j;
         for (j=degR; j>=1; j--)
            cpGFpElementCopy(GFPX_IDX_ELEMENT(pTmpResult, j, groundElemLen), GFPX_IDX_ELEMENT(pTmpResult, j-1, groundElemLen), groundElemLen);
         cpGFpElementPadd(pTmpResult, groundElemLen, 0);
      }

      cpGFpxMul_GFE(pTmpProduct, pGFpolynomial, r, pGFEx);
      GFP_METHOD(pGFEx)->sub(pTmpResult, pTmpResult, pTmpProduct, pGFEx);

      /* B[degB-i] */
      pTmpB -= groundElemLen;
      cpGFpxMul_GFE(pTmpProduct, pA, pTmpB, pGFEx);
      GFP_METHOD(pGFEx)->add(pTmpResult, pTmpResult, pTmpProduct, pGFEx);
   }

   /* copy result */
   cpGFpElementCopy(pR, pTmpResult, elemLen);

   /* release pools */
   cpGFpReleasePool(1, pGroundGFE);
   cpGFpReleasePool(2, pGFEx);

   return pR;
}

BNU_CHUNK_T* cpGFpxSqr_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsEngine* pGFEx)
{
   int extDegree = GFP_EXTDEGREE(pGFEx);

   BNU_CHUNK_T* pGFpolynomial = GFP_MODULUS(pGFEx);
   int degR = extDegree-1;
   int elemLen= GFP_FELEN(pGFEx);

   int degA = degR;
   BNU_CHUNK_T* pTmpProduct = cpGFpGetPool(2, pGFEx);
   BNU_CHUNK_T* pTmpResult = pTmpProduct + GFP_PELEN(pGFEx);

   gsEngine* pGroundGFE = GFP_PARENT(pGFEx);
   BNU_CHUNK_T* r = cpGFpGetPool(1, pGroundGFE);
   int groundElemLen = GFP_FELEN(pGroundGFE);

   const BNU_CHUNK_T* pTmpA = GFPX_IDX_ELEMENT(pA, degA, groundElemLen);

    //gres: temporary excluded: assert(NULL!=pTmpProduct && NULL!=r);

   /* clear temporary */
   cpGFpElementPadd(pTmpProduct, elemLen, 0);

   /* R = A * A[degA-1] */
   cpGFpxMul_GFE(pTmpResult, pA, pTmpA, pGFEx);

   for(degA-=1; degA>=0; degA--) {
      /* save R[degR-1] */
      cpGFpElementCopy(r, GFPX_IDX_ELEMENT(pTmpResult, degR, groundElemLen), groundElemLen);

      { /* R = R * x */
         int j;
         for (j=degR; j>=1; j--)
            cpGFpElementCopy(GFPX_IDX_ELEMENT(pTmpResult, j, groundElemLen), GFPX_IDX_ELEMENT(pTmpResult, j-1, groundElemLen), groundElemLen);
         cpGFpElementPadd(pTmpResult, groundElemLen, 0);
      }

      cpGFpxMul_GFE(pTmpProduct, pGFpolynomial, r, pGFEx);
      GFP_METHOD(pGFEx)->sub(pTmpResult, pTmpResult, pTmpProduct, pGFEx);

      /* A[degA-i] */
      pTmpA -= groundElemLen;
      cpGFpxMul_GFE(pTmpProduct, pA, pTmpA, pGFEx);
      GFP_METHOD(pGFEx)->add(pTmpResult, pTmpResult, pTmpProduct, pGFEx);
   }

   /* copy result */
   cpGFpElementCopy(pR, pTmpResult, elemLen);

   /* release pools */
   cpGFpReleasePool(1, pGroundGFE);
   cpGFpReleasePool(2, pGFEx);

   return pR;
}

BNU_CHUNK_T* cpGFpxDiv2_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsEngine* pGFEx)
{
   gsEngine* pBasicGFE = cpGFpBasic(pGFEx);
   mod_div2 div2F = GFP_METHOD(pBasicGFE)->div2;
   int basicElemLen = GFP_FELEN(pBasicGFE);
   int basicDeg = cpGFpBasicDegreeExtension(pGFEx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      div2F(pTmp, pA, pBasicGFE);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxMul2_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsEngine* pGFEx)
{
   gsEngine* pBasicGFE = cpGFpBasic(pGFEx);
   mod_mul2 mul2F = GFP_METHOD(pBasicGFE)->mul2;
   int basicElemLen = GFP_FELEN(pBasicGFE);
   int basicDeg = cpGFpBasicDegreeExtension(pGFEx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      mul2F(pTmp, pA, pBasicGFE);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxMul3_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsEngine* pGFEx)
{
   gsEngine* pBasicGFE = cpGFpBasic(pGFEx);
   mod_mul3 mul3F = GFP_METHOD(pBasicGFE)->mul3;
   int basicElemLen = GFP_FELEN(pBasicGFE);
   int basicDeg = cpGFpBasicDegreeExtension(pGFEx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      mul3F(pTmp, pA, pBasicGFE);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxEncode_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsEngine* pGFEx)
{
   gsEngine* pBasicGFE = cpGFpBasic(pGFEx);
   mod_encode encodeF = GFP_METHOD(pBasicGFE)->encode;
   int basicElemLen = GFP_FELEN(pBasicGFE);
   int basicDeg = cpGFpBasicDegreeExtension(pGFEx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      encodeF(pTmp, pA, pBasicGFE);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxDecode_com(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsEngine* pGFEx)
{
   gsEngine* pBasicGFE = cpGFpBasic(pGFEx);
   mod_decode decodeF = GFP_METHOD(pBasicGFE)->decode;
   int basicElemLen = GFP_FELEN(pBasicGFE);
   int basicDeg = cpGFpBasicDegreeExtension(pGFEx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      decodeF(pTmp, pA, pBasicGFE);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

/*
// return common polynomi alarith methods
*/
static gsModMethod* gsPolyArith(void)
{
   static gsModMethod m = {
      cpGFpxEncode_com,
      cpGFpxDecode_com,
      cpGFpxMul_com,
      cpGFpxSqr_com,
      NULL,
      cpGFpxAdd_com,
      cpGFpxSub_com,
      cpGFpxNeg_com,
      cpGFpxDiv2_com,
      cpGFpxMul2_com,
      cpGFpxMul3_com,
      //cpGFpxInv
   };
   return &m;
}

IPPFUN( const IppsGFpMethod*, ippsGFpxMethod_com, (void) )
{
   static IppsGFpMethod method = {
      cpID_Poly,
      0,
      NULL,
      NULL
   };
   method.arith = gsPolyArith();
   return &method;
}
