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
//     Internal operations over prime GF(p).
//
//     Context:
//        cpGFpRand
//        cpGFpSet
//        cpGFpGet
//
//        cpGFpNeg
//        cpGFpInv
//        cpGFpHalve
//        cpGFpAdd
//        cpGFpSub
//        cpGFpMul
//        cpGFpSqr
//        cpGFpExp, cpGFpExp2
//        cpGFpSqrt
//
*/
#include "owncp.h"

#include "pcpbn.h"
#include "pcpgfpstuff.h"

//gres: temporary excluded: #include <assert.h>

BNU_CHUNK_T* cpGFpRand(BNU_CHUNK_T* pR, gsModEngine* pGFE, IppBitSupplier rndFunc, void* pRndParam)
{
   int elemLen = GFP_FELEN(pGFE);
   int reqBitSize = GFP_FEBITLEN(pGFE)+GFP_RAND_ADD_BITS;
   int nsR = (reqBitSize +BITSIZE(BNU_CHUNK_T)-1)/BITSIZE(BNU_CHUNK_T);

   int internal_err;

   BNU_CHUNK_T* pPool = cpGFpGetPool(2, pGFE);
   //gres: temporary excluded: assert(pPool!=NULL);

   cpGFpElementPadd(pPool, nsR, 0);

   internal_err = ippStsNoErr != rndFunc((Ipp32u*)pPool, reqBitSize, pRndParam);

   if(!internal_err) {
      nsR = cpMod_BNU(pPool, nsR, GFP_MODULUS(pGFE), elemLen);
      cpGFpElementPadd(pPool+nsR, elemLen-nsR, 0);
      GFP_METHOD(pGFE)->encode(pR, pPool, pGFE);
   }

   cpGFpReleasePool(2, pGFE);
   return internal_err? NULL : pR;
}

BNU_CHUNK_T* cpGFpSet(BNU_CHUNK_T* pElm, const BNU_CHUNK_T* pDataA, int nsA, gsModEngine* pGFE)
{
   const BNU_CHUNK_T* pModulus = GFP_MODULUS(pGFE);
   int elemLen = GFP_FELEN(pGFE);

   if(0 <= cpCmp_BNU(pDataA, nsA, pModulus, elemLen))
      return NULL;
   else {
      BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGFE);
      //gres: temporary excluded: assert(pTmp !=NULL);

      ZEXPAND_COPY_BNU(pTmp, elemLen, pDataA, nsA);
      GFP_METHOD(pGFE)->encode(pElm, pTmp, pGFE);

      cpGFpReleasePool(1, pGFE);
      return pElm;
   }
}

BNU_CHUNK_T* cpGFpGet(BNU_CHUNK_T* pDataA, int nsA, const BNU_CHUNK_T* pElm, gsModEngine* pGFE)
{
   int elemLen = GFP_FELEN(pGFE);

   BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGFE);
   //gres: temporary excluded: assert(pTmp !=NULL);

   GFP_METHOD(pGFE)->decode(pTmp, pElm, pGFE);
   ZEXPAND_COPY_BNU(pDataA, nsA, pTmp, elemLen);

   cpGFpReleasePool(1, pGFE);
   return pDataA;
}

BNU_CHUNK_T* cpGFpSetOctString(BNU_CHUNK_T* pElm, const Ipp8u* pStr, int strSize, gsModEngine* pGFE)
{
   int elemLen = GFP_FELEN(pGFE);

   if((int)(elemLen*sizeof(BNU_CHUNK_T)) < strSize)
      return NULL;

   {
      BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGFE);
      //gres: temporary excluded: assert(pTmp !=NULL);
      {
         int nsTmp = cpFromOctStr_BNU(pTmp, pStr, strSize);
         BNU_CHUNK_T* ret = cpGFpSet(pElm, pTmp, nsTmp, pGFE);

         cpGFpReleasePool(1, pGFE);
         return ret==NULL? NULL : pElm;
      }
   }
}

Ipp8u* cpGFpGetOctString(Ipp8u* pStr, int strSize, const BNU_CHUNK_T* pElm, gsModEngine* pGFE)
{
   int elemLen = GFP_FELEN(pGFE);

   BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGFE);
   //gres: temporary excluded: assert(pTmp !=NULL);

   GFP_METHOD(pGFE)->decode(pTmp, pElm, pGFE);
   cpToOctStr_BNU(pStr, strSize, pTmp, elemLen);

   cpGFpReleasePool(1, pGFE);
   return pStr;
}

BNU_CHUNK_T* cpGFpAdd(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, gsModEngine* pGFE)
{
   return GFP_METHOD(pGFE)->add(pR, pA, pB, pGFE);
}

BNU_CHUNK_T* cpGFpSub(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, gsModEngine* pGFE)
{
   return GFP_METHOD(pGFE)->sub(pR, pA, pB, pGFE);
}

BNU_CHUNK_T* cpGFpNeg(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsModEngine* pGFE)
{
   return GFP_METHOD(pGFE)->neg(pR, pA, pGFE);
}

BNU_CHUNK_T* cpGFpMul(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, gsModEngine* pGFE)
{
   return GFP_METHOD(pGFE)->mul(pR, pA, pB, pGFE);
}

BNU_CHUNK_T* cpGFpSqr(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsModEngine* pGFE)
{
   return GFP_METHOD(pGFE)->sqr(pR, pA, pGFE);
}

BNU_CHUNK_T* cpGFpHalve(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsModEngine* pGFE)
{
   return GFP_METHOD(pGFE)->div2(pR, pA, pGFE);
}

BNU_CHUNK_T* cpGFpInv(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsModEngine* pGFE)
{
   GFP_METHOD(pGFE)->decode(pR, pA, pGFE);
   gs_mont_inv(pR, pR, pGFE);
   return pR;
}

BNU_CHUNK_T* cpGFpExp(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pE, int nsE, gsModEngine* pGFE)
{
   int elemLen = GFP_FELEN(pGFE);
   cpMontExpBin_BNU(pR, pA,cpFix_BNU(pA, elemLen), pE,cpFix_BNU(pE, nsE), pGFE);
   return pR;
}

static int factor2(BNU_CHUNK_T* pA, int nsA)
{
   int factor = 0;
   int bits;

   int i;
   for(i=0; i<nsA; i++) {
      int ntz = cpNTZ_BNU(pA[i]);
      factor += ntz;
      if(ntz<BITSIZE(BNU_CHUNK_T))
         break;
   }

   bits = factor;
   if(bits >= BITSIZE(BNU_CHUNK_T)) {
      int nchunk = bits/BITSIZE(BNU_CHUNK_T);
      cpGFpElementCopyPadd(pA, nsA, pA+nchunk, nsA-nchunk);
      bits %= BITSIZE(BNU_CHUNK_T);
   }
   if(bits)
      cpLSR_BNU(pA, pA, nsA, bits);

   return factor;
}

static BNU_CHUNK_T* cpGFpExp2(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, int e, gsModEngine* pGFE)
{
   cpGFpElementCopy(pR, pA, GFP_FELEN(pGFE));
   while(e--) {
      GFP_METHOD(pGFE)->sqr(pR, pR, pGFE);
   }
   return pR;
}

/* returns:
   0, if a - qnr
   1, if sqrt is found
*/
int cpGFpSqrt(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsModEngine* pGFE)
{
   int elemLen = GFP_FELEN(pGFE);
   int poolelementLen = GFP_PELEN(pGFE);
   int resultFlag = 1;

   /* case A==0 */
   if( GFP_IS_ZERO(pA, elemLen) )
      cpGFpElementPadd(pR, elemLen, 0);

   /* general case */
   else {
      BNU_CHUNK_T* q = cpGFpGetPool(4, pGFE);
      BNU_CHUNK_T* x = q + poolelementLen;
      BNU_CHUNK_T* y = x + poolelementLen;
      BNU_CHUNK_T* z = y + poolelementLen;

      int s;

      //gres: temporary excluded: assert(q!=NULL);

      /* z=1 */
      GFP_ONE(z, elemLen);

      /* (modulus-1) = 2^s*q */
      cpSub_BNU(q, GFP_MODULUS(pGFE), z, elemLen);
      s = factor2(q, elemLen);

      /*
      // initialization
      */

      /* y = qnr^q */
      cpGFpExp(y, GFP_QNR(pGFE), q,elemLen, pGFE);
      /* x = a^((q-1)/2) */
      cpSub_BNU(q, q, z, elemLen);
      cpLSR_BNU(q, q, elemLen, 1);
      cpGFpExp(x, pA, q, elemLen, pGFE);
      /* z = a*x^2 */
      GFP_METHOD(pGFE)->mul(z, x, x, pGFE);
      GFP_METHOD(pGFE)->mul(z, pA, z, pGFE);
      /* R = a*x */
      GFP_METHOD(pGFE)->mul(pR, pA, x, pGFE);

      while( !GFP_EQ(z, MOD_MNT_R(pGFE), elemLen) ) {
         int m = 0;
         cpGFpElementCopy(q, z, elemLen);

         for(m=1; m<s; m++) {
            GFP_METHOD(pGFE)->mul(q, q, q, pGFE);
            if( GFP_EQ(q, MOD_MNT_R(pGFE), elemLen) )
               break;
         }

         if(m==s) {
            /* A is quadratic non-residue */
            resultFlag = 0;
            break;
         }
         else {
            /* exponent reduction */
            cpGFpExp2(q, y, (s-m-1), pGFE);           /* q = y^(2^(s-m-1)) */
            GFP_METHOD(pGFE)->mul(y, q, q, pGFE);     /* y = q^2 */
            GFP_METHOD(pGFE)->mul(pR, q, pR, pGFE);   /* R = q*R */
            GFP_METHOD(pGFE)->mul(z, y, z, pGFE);     /* z = z*y */
            s = m;
         }
      }

      /* choose smallest between R and (modulus-R) */
      GFP_METHOD(pGFE)->decode(q, pR, pGFE);
      if(GFP_GT(q, GFP_HMODULUS(pGFE), elemLen))
         GFP_METHOD(pGFE)->neg(pR, pR, pGFE);

      cpGFpReleasePool(4, pGFE);
   }

   return resultFlag;
}
