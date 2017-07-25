/*############################################################################
  # Copyright 2010-2017 Intel Corporation
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
//     Internal operations over GF(p).
//
//     Context:
//        cpGFpCmpare
//
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
//        cpGFpExp, cpGFpExp2
//        cpGFpSqrt
//
*/
#include "owndefs.h"
#include "owncp.h"

#include "pcpgfpstuff.h"
#include "pcpgfpmethod.h"


BNU_CHUNK_T* cpGFpSet(BNU_CHUNK_T* pElm, const BNU_CHUNK_T* pDataA, int nsA, IppsGFpState* pGFp)
{
   const BNU_CHUNK_T* pModulus = GFP_MODULUS(pGFp);
   int elemLen = GFP_FELEN(pGFp);

   if(0 <= cpCmp_BNU(pDataA, nsA, pModulus, elemLen))
      return NULL;
   else {
      BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGFp);
      ZEXPAND_COPY_BNU(pTmp, elemLen, pDataA, nsA);
      pGFp->encode(pElm, pTmp, pGFp);
      cpGFpReleasePool(1, pGFp);
      return pElm;
   }
}

BNU_CHUNK_T* cpGFpGet(BNU_CHUNK_T* pDataA, int nsA, const BNU_CHUNK_T* pElm, IppsGFpState* pGFp)
{
   int elemLen = GFP_FELEN(pGFp);
   BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGFp);

   pGFp->decode(pTmp, pElm, pGFp);
   ZEXPAND_COPY_BNU(pDataA, nsA, pTmp, elemLen);
   cpGFpReleasePool(1, pGFp);
   return pDataA;
}

BNU_CHUNK_T* cpGFpSetOctString(BNU_CHUNK_T* pElm, const Ipp8u* pStr, int strSize, IppsGFpState* pGFp)
{
   int elemLen = GFP_FELEN(pGFp);

   if((int)(elemLen*sizeof(BNU_CHUNK_T)) < strSize)
      return NULL;

   else {
      BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGFp);

      int len = cpFromOctStr_BNU(pTmp, pStr, strSize);
      ZEXPAND_BNU(pTmp+len, elemLen-len, 0);
      //pElm = pGFp->encode(pElm, pTmp, pGFp);
      pGFp->encode(pElm, pTmp, pGFp);

      cpGFpReleasePool(1, pGFp);
      return pElm;
   }
}

Ipp8u* cpGFpGetOctString(Ipp8u* pStr, int strSize, const BNU_CHUNK_T* pElm, IppsGFpState* pGFp)
{
   BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGFp);
   int elemLen = GFP_FELEN(pGFp);

   pGFp->decode(pTmp, pElm, pGFp);
   cpToOctStr_BNU(pStr, strSize, pTmp, elemLen);

   cpGFpReleasePool(1, pGFp);
   return pStr;
}

BNU_CHUNK_T* cpGFpAdd(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGFp)
{
   return pGFp->add(pR, pA, pB, pGFp);
}


BNU_CHUNK_T* cpGFpSub(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGFp)
{
   return pGFp->sub(pR, pA, pB, pGFp);
}

BNU_CHUNK_T* cpGFpNeg(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFp)
{
   return pGFp->neg(pR, pA, pGFp);
}

BNU_CHUNK_T* cpGFpMul(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pB, IppsGFpState* pGFp)
{
   return pGFp->mul(pR, pA, pB, pGFp);
}

BNU_CHUNK_T* cpGFpSqr(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFp)
{
   return pGFp->sqr(pR, pA, pGFp);
}

BNU_CHUNK_T* cpGFpHalve(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFp)
{
   return pGFp->div2(pR, pA, pGFp);
}


BNU_CHUNK_T* cpGFpInv(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFp)
{
   BNU_CHUNK_T* pModulus = GFP_MODULUS(pGFp);
   int elemLen   = GFP_FELEN(pGFp);
   int poolelementLen= GFP_PELEN(pGFp);

   BNU_CHUNK_T* tmpM = cpGFpGetPool(4, pGFp);
   BNU_CHUNK_T* tmpX1= tmpM +poolelementLen;
   BNU_CHUNK_T* tmpX2= tmpX1+poolelementLen;
   BNU_CHUNK_T* tmpX3= tmpX2+poolelementLen;
   int nsR;

   cpGFpElementCopy(tmpM, pModulus, elemLen);
   nsR = cpModInv_BNU(pR, pA,elemLen, tmpM, elemLen, tmpX1,tmpX2,tmpX3);
   cpGFpReleasePool(4, pGFp);

   cpGFpElementPadd(pR+nsR, elemLen-nsR, 0);
   return pGFp->mul(pR, pR, MNT_CUBE_R(GFP_MONT(pGFp)), pGFp);
}

BNU_CHUNK_T* cpGFpExp(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pE, int nsE, IppsGFpState* pGFp)
{
   IppsBigNumState A;
   IppsBigNumState E;
   IppsBigNumState R;

   BNU_CHUNK_T* pPool = cpGFpGetPool(3, pGFp);
   int poolElemLen = GFP_PELEN(pGFp);
   int elemLen = GFP_FELEN(pGFp);

   cpGFpSetBigNum(&A, elemLen, pA, pPool+0*poolElemLen);
   cpGFpSetBigNum(&E, nsE, pE, pPool+1*poolElemLen);
   cpGFpInitBigNum(&R,elemLen, pR, pPool+2*poolElemLen);

   cpMontExpBin_BN(&R, &A, &E, GFP_MONT(pGFp));

   cpGFpReleasePool(3, pGFp);
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

static BNU_CHUNK_T* cpGFpExp2(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, int e, IppsGFpState* pGFp)
{
   cpGFpElementCopy(pR, pA, GFP_FELEN(pGFp));
   while(e--) {
      pGFp->sqr(pR, pR, pGFp);
   }
   return pR;
}

/* returns:
   0, if a - qnr
   1, if sqrt is found
*/
int cpGFpSqrt(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFp)
{
   int elemLen = GFP_FELEN(pGFp);
   int poolelementLen = GFP_PELEN(pGFp);
   int resultFlag = 1;

   /* case A==0 */
   if( GFP_IS_ZERO(pA, elemLen) )
      cpGFpElementPadd(pR, elemLen, 0);

   /* general case */
   else {
      BNU_CHUNK_T* q = cpGFpGetPool(4, pGFp);
      BNU_CHUNK_T* x = q + poolelementLen;
      BNU_CHUNK_T* y = x + poolelementLen;
      BNU_CHUNK_T* z = y + poolelementLen;

      int s;

      /* z=1 */
      GFP_ONE(z, elemLen);

      /* (modulus-1) = 2^s*q */
      cpSub_BNU(q, GFP_MODULUS(pGFp), z, elemLen);
      s = factor2(q, elemLen);

      /*
      // initialization
      */

      /* y = qnr^q */
      cpGFpExp(y, GFP_QNR(pGFp), q,elemLen, pGFp);
      /* x = a^((q-1)/2) */
      cpSub_BNU(q, q, z, elemLen);
      cpLSR_BNU(q, q, elemLen, 1);
      cpGFpExp(x, pA, q, elemLen, pGFp);
      /* z = a*x^2 */
      pGFp->mul(z, x, x, pGFp);
      pGFp->mul(z, pA, z, pGFp);
      /* R = a*x */
      pGFp->mul(pR, pA, x, pGFp);

      while( !GFP_EQ(z, MNT_1(GFP_MONT(pGFp)), elemLen) ) {
         int m = 0;
         cpGFpElementCopy(q, z, elemLen);

         for(m=1; m<s; m++) {
            pGFp->mul(q, q, q, pGFp);
            if( GFP_EQ(q, MNT_1(GFP_MONT(pGFp)), elemLen) )
               break;
         }

         if(m==s) {
            /* A is quadratic non-residue */
            resultFlag = 0;
            break;
         }
         else {
            /* exponent reduction */
            cpGFpExp2(q, y, (s-m-1), pGFp);   /* q = y^(2^(s-m-1)) */
            pGFp->mul(y, q, q, pGFp);          /* y = q^2 */
            pGFp->mul(pR, q, pR, pGFp);        /* R = q*R */
            pGFp->mul(z, y, z, pGFp);          /* z = z*y */
            s = m;
         }
      }

      /* choose smallest between R and (modulus-R) */
      pGFp->decode(q, pR, pGFp);
      if(GFP_GT(q, GFP_HMODULUS(pGFp), elemLen))
         pGFp->neg(pR, pR, pGFp);

      cpGFpReleasePool(4, pGFp);
   }

   return resultFlag;
}


BNU_CHUNK_T* cpGFpRand(BNU_CHUNK_T* pR, IppsGFpState* pGFp, IppBitSupplier rndFunc, void* pRndParam)
{
   int elemLen = GFP_FELEN(pGFp);
///int reqBitSize = GFP_FEBITSIZE(pGFp)+GF_RAND_ADD_BITS;
   int reqBitSize = GFP_FEBITLEN(pGFp)+GF_RAND_ADD_BITS;
   int nsR = (reqBitSize +BITSIZE(BNU_CHUNK_T)-1)/BITSIZE(BNU_CHUNK_T);

   BNU_CHUNK_T* pPool = cpGFpGetPool(2, pGFp);
   cpGFpElementPadd(pPool, nsR, 0);
   rndFunc((Ipp32u*)pPool, reqBitSize, pRndParam);

   nsR = cpMod_BNU(pPool, nsR, GFP_MODULUS(pGFp), elemLen);
   cpGFpElementPadd(pPool+nsR, elemLen-nsR, 0);

   pGFp->encode(pR, pPool, pGFp);

   cpGFpReleasePool(2, pGFp);
   return pR;
}
