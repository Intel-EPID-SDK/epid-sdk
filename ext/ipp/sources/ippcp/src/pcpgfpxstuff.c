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
//     Internal operations over GF(p) extension.
// 
//     Context:
//        cpGFpxCmpare
//        cpGFpxSet
//        cpGFpxRand
//        cpGFpxGet
// 
//        cpGFpxHalve
//        cpGFpxAdd, cpGFpxAdd_GFE
//        cpGFpxSub, cpGFpxSub_GFE
//        cpGFpxMul, cpGFpxMul_GFE
//        cpGFp2biMul, cpGFp3biMul, cpGFpxMul_G0
//        cpGFpxSqr
//        cpGFp2biSqr, cpGFp3biSqr
//        cpGFpxNeg
//        cpGFpxInv
//        cpGFpxExp
//        cpGFpxMultiExp
//        cpGFpxConj
// 
// 
*/
#include "owndefs.h"
#include "owncp.h"


#include "pcpgfpxstuff.h"

#if defined(__GNUC__) && (__GNUC__ >= 6)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmisleading-indentation"
#endif


BNU_CHUNK_T* cpGFpxRand(BNU_CHUNK_T* pR, IppsGFpState* pGFpx, IppBitSupplier rndFunc, void* pRndParam)
{
   if( GFP_IS_BASIC(pGFpx) )
      return cpGFpRand(pR, pGFpx, rndFunc, pRndParam);

   else {
      IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);
      int basicElemLen = GFP_FELEN(pBasicGF);
      int basicDeg = cpGFpBasicDegreeExtension(pGFpx);

      BNU_CHUNK_T* pTmp = pR;
      int deg;
      for(deg=0; deg<basicDeg; deg++) {
         cpGFpRand(pTmp, pBasicGF, rndFunc, pRndParam);
         pTmp += basicElemLen;
      }
      return pR;
   }
}

BNU_CHUNK_T* cpGFpxSet(BNU_CHUNK_T* pE, const BNU_CHUNK_T* pDataA, int nsA, IppsGFpState* pGFpx)
{
   if( GFP_IS_BASIC(pGFpx) )
      return cpGFpSet(pE, pDataA, nsA, pGFpx);

   else {
      IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);
      int basicElemLen = GFP_FELEN(pBasicGF);

      BNU_CHUNK_T* pTmpE = pE;
      int basicDeg = cpGFpBasicDegreeExtension(pGFpx);

      int deg, error;
      for(deg=0, error=0; deg<basicDeg && !error; deg++) {
         int pieceA = IPP_MIN(nsA, basicElemLen);

         error = NULL == cpGFpSet(pTmpE, pDataA, pieceA, pBasicGF);
         pTmpE   += basicElemLen;
         pDataA += pieceA;
         nsA -= pieceA;
      }

      return (deg<basicDeg)? NULL : pE;
   }
}

BNU_CHUNK_T* cpGFpxSetPolyTerm(BNU_CHUNK_T* pE, int deg, const BNU_CHUNK_T* pDataA, int nsA, IppsGFpState* pGFpx)
{
   pE += deg * GFP_FELEN(pGFpx);
   return cpGFpxSet(pE, pDataA, nsA, pGFpx);
}

BNU_CHUNK_T* cpGFpxGet(BNU_CHUNK_T* pDataA, int nsA, const BNU_CHUNK_T* pE, IppsGFpState* pGFpx)
{
   cpGFpElementPadd(pDataA, nsA, 0);

   if( GFP_IS_BASIC(pGFpx) )
      return cpGFpGet(pDataA, nsA, pE, pGFpx);

   else {
      IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);
      int basicElemLen = GFP_FELEN(pBasicGF);

      BNU_CHUNK_T* pTmp = pDataA;
      int basicDeg = cpGFpBasicDegreeExtension(pGFpx);

      int deg;
      for(deg=0; deg<basicDeg && nsA>0; deg++) {
         int pieceA = IPP_MIN(nsA, basicElemLen);

         cpGFpGet(pTmp, pieceA, pE, pBasicGF);
         pE   += basicElemLen;
         pTmp += pieceA;
         nsA -= pieceA;
      }

      return pDataA;
   }
}

BNU_CHUNK_T* cpGFpxGetPolyTerm(BNU_CHUNK_T* pDataA, int nsA, const BNU_CHUNK_T* pE, int deg, IppsGFpState* pGFpx)
{
   pE += deg * GFP_FELEN(pGFpx);
   return cpGFpxGet(pDataA, nsA, pE, pGFpx);
}

BNU_CHUNK_T* cpGFpxConj(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
   int groundElemLen = GFP_FELEN(pGroundGF);

   if(pR != pA)
      cpGFpElementCopy(pR, pA, groundElemLen);
   //cpGFpxNeg(pR+groundElemLen, pA+groundElemLen, pGroundGF);
   pGroundGF->neg(pR+groundElemLen, pA+groundElemLen, pGroundGF);

   return pR;
}


BNU_CHUNK_T* cpGFpxAdd_GFE(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pGroundB, IppsGFpState* pGFpx)
{
   IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);

   if(pR != pA) {
      int groundElemLen = GFP_FELEN(pGroundGF);
      int deg = GFP_DEGREE(pGFpx);
      cpGFpElementCopy(pR+groundElemLen, pA+groundElemLen, groundElemLen*(deg-1));
   }
   return pGroundGF->add(pR, pA, pGroundB, pGroundGF);
}

BNU_CHUNK_T* cpGFpxSub_GFE(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pGroundB, IppsGFpState* pGFpx)
{
   IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);

   if(pR != pA) {
      int groundElemLen = GFP_FELEN(pGroundGF);
      int deg = GFP_DEGREE(pGFpx);
      cpGFpElementCopy(pR+groundElemLen, pA+groundElemLen, groundElemLen*(deg-1));
   }
   return pGroundGF->sub(pR, pA, pGroundB, pGroundGF);
}

BNU_CHUNK_T* cpGFpxMul_GFE(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pGroundB, IppsGFpState* pGFpx)
{
   IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
   int grounfElemLen = GFP_FELEN(pGroundGF);

   BNU_CHUNK_T* pTmp = pR;

   int deg;
   for(deg=0; deg<GFP_DEGREE(pGFpx); deg++) {
      pGroundGF->mul(pTmp, pA, pGroundB, pGroundGF);
      pTmp += grounfElemLen;
      pA += grounfElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxNeg(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
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

static BNU_CHUNK_T* gfpxPolyDiv(BNU_CHUNK_T* pQ, BNU_CHUNK_T* pR,
                        const BNU_CHUNK_T* pA,
                        const BNU_CHUNK_T* pB,
                        IppsGFpState* pGFpx)
{
   if( GFP_IS_BASIC(pGFpx) )
      return NULL;

   else {
      int elemLen = GFP_FELEN(pGFpx);
      IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
      int termLen = GFP_FELEN(pGroundGF);

      int degA = degree(pA, pGFpx);
      int degB = degree(pB, pGFpx);

      if(degB==0) {
         if( GFP_IS_ZERO(pB, termLen) )
            return NULL;
         else {
            IppsGFpState* pBasicGF = cpGFpBasic(pGroundGF);

            cpGFpInv(pR, pB, pBasicGF);
            cpGFpElementPadd(pR+GFP_FELEN(pGroundGF), termLen-GFP_FELEN(pGroundGF), 0);
            cpGFpxMul_GFE(pQ, pA, pR, pGFpx);
            cpGFpElementPadd(pR, elemLen, 0);
            return pR;
         }
      }

      if(degA < degB) {
         cpGFpElementPadd(pQ, elemLen, 0);
         cpGFpElementCopyPadd(pR, elemLen, pA, (degA+1)*termLen);
         return pR;
      }

      else {
         int i, j;
         BNU_CHUNK_T* pProduct = cpGFpGetPool(2, pGroundGF);
         BNU_CHUNK_T* pInvB = pProduct + GFP_PELEN(pGroundGF);

         cpGFpElementCopyPadd(pR, elemLen, pA, (degA+1)*termLen);
         cpGFpElementPadd(pQ, elemLen, 0);

         cpGFpxInv(pInvB, GFPX_IDX_ELEMENT(pB, degB, termLen), pGroundGF);

         for(i=0; i<=degA-degB && !GFP_IS_ZERO(GFPX_IDX_ELEMENT(pR, degA-i, termLen), termLen); i++) {
            /* compute q term */
            pGroundGF->mul(GFPX_IDX_ELEMENT(pQ, degA-degB-i, termLen),
                      GFPX_IDX_ELEMENT(pR, degA-i, termLen),
                      pInvB,
                      pGroundGF);

            /* R -= B * q */
            cpGFpElementPadd(GFPX_IDX_ELEMENT(pR, degA-i, termLen), termLen, 0);
            for(j=0; j<degB; j++) {
               pGroundGF->mul(pProduct,
                         GFPX_IDX_ELEMENT(pB, j ,termLen),
                         GFPX_IDX_ELEMENT(pQ, degA-degB-i, termLen),
                         pGroundGF);
               pGroundGF->sub(GFPX_IDX_ELEMENT(pR, degA-degB-i+j, termLen),
                         GFPX_IDX_ELEMENT(pR, degA-degB-i+j, termLen),
                         pProduct,
                         pGroundGF);
            }
         }

         cpGFpReleasePool(2, pGroundGF);
         return pR;
      }
   }
}

static BNU_CHUNK_T* gfpxGeneratorDiv(BNU_CHUNK_T* pQ, BNU_CHUNK_T* pR, const BNU_CHUNK_T* pB, IppsGFpState* pGFpx)
{
   if( GFP_IS_BASIC(pGFpx) )
      return NULL;

   else {
      int elemLen = GFP_FELEN(pGFpx);
      IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
      int termLen = GFP_FELEN(pGroundGF);

      BNU_CHUNK_T* pInvB = cpGFpGetPool(2, pGroundGF);
      BNU_CHUNK_T* pTmp  = pInvB + GFP_PELEN(pGroundGF);

      int degB = degree(pB, pGFpx);
      int i;

      cpGFpElementCopy(pR, GFP_MODULUS(pGFpx), elemLen);
      cpGFpElementPadd(pQ, elemLen, 0);

      cpGFpxInv(pInvB, GFPX_IDX_ELEMENT(pB, degB, termLen), pGroundGF);

      for(i=0; i<degB; i++) {
         BNU_CHUNK_T* ptr;
         pGroundGF->mul(pTmp, pInvB, GFPX_IDX_ELEMENT(pB, i, termLen), pGroundGF);
         ptr = GFPX_IDX_ELEMENT(pR, GFP_DEGREE(pGFpx)-degB+i, termLen);
         pGroundGF->sub(ptr, ptr, pTmp, pGroundGF);
      }

      gfpxPolyDiv(pQ, pR, pR, pB, pGFpx);

      cpGFpElementCopy(GFPX_IDX_ELEMENT(pQ, GFP_DEGREE(pGFpx)-degB, termLen), pInvB, termLen);

      cpGFpReleasePool(2, pGroundGF);
      return pR;
   }
}

BNU_CHUNK_T* cpGFpxInv(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, IppsGFpState* pGFpx)
{
   if( GFP_IS_BASIC(pGFpx) )
      return cpGFpInv(pR, pA, pGFpx);

   if(0==degree(pA, pGFpx)) {
      IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
      BNU_CHUNK_T* tmpR = cpGFpGetPool(1, pGroundGF);

      cpGFpxInv(tmpR, pA, pGroundGF);

      cpGFpElementCopyPadd(pR, GFP_FELEN(pGFpx), tmpR, GFP_FELEN(pGroundGF));
      cpGFpReleasePool(1, pGroundGF);
      return pR;
   }

   else {
      int elemLen = GFP_FELEN(pGFpx);
      IppsGFpState* pGroundGF = GFP_GROUNDGF(pGFpx);
      IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);

      int pxVars = 6;
      int pelemLen = GFP_PELEN(pGFpx);
      BNU_CHUNK_T* lastrem = cpGFpGetPool(pxVars, pGFpx);
      BNU_CHUNK_T* rem     = lastrem + pelemLen;
      BNU_CHUNK_T* quo     = rem +  pelemLen;
      BNU_CHUNK_T* lastaux = quo + pelemLen;
      BNU_CHUNK_T* aux     = lastaux + pelemLen;
      BNU_CHUNK_T* temp    = aux + pelemLen;

      cpGFpElementCopy(lastrem, pA, elemLen);
      cpGFpElementCopyPadd(lastaux, elemLen, MNT_1(GFP_MONT(pBasicGF)), GFP_FELEN(pBasicGF));

      gfpxGeneratorDiv(quo, rem, pA, pGFpx);
      cpGFpxNeg(aux, quo, pGFpx);

      while(degree(rem, pGFpx) > 0) {
         gfpxPolyDiv(quo, temp, lastrem, rem, pGFpx);
         SWAP_PTR(BNU_CHUNK_T, rem, lastrem); //
         SWAP_PTR(BNU_CHUNK_T, temp, rem);

         pGFpx->neg(quo, quo, pGFpx);
         pGFpx->mul(temp, quo, aux, pGFpx);
         pGFpx->add(temp, lastaux, temp, pGFpx);
         SWAP_PTR(BNU_CHUNK_T, aux, lastaux);
         SWAP_PTR(BNU_CHUNK_T, temp, aux);
      }
      if (GFP_IS_ZERO(rem, elemLen)) { /* gcd != 1 */
         cpGFpReleasePool(pxVars, pGFpx);
         return NULL;
      }

      {
         BNU_CHUNK_T* invRem  = cpGFpGetPool(1, pGroundGF);

         cpGFpxInv(invRem, rem, pGroundGF);
         cpGFpxMul_GFE(pR, aux, invRem, pGFpx);

         cpGFpReleasePool(1, pGroundGF);
      }

      cpGFpReleasePool(pxVars, pGFpx);

      return pR;
   }
}


static int div_upper(int a, int d)
{ return (a+d-1)/d; }

static int getNumOperations(int bitsize, int w)
{
   int n_overhead = (1<<w) -1;
   int n_ops = div_upper(bitsize, w) + n_overhead;
   return n_ops;
}
int cpGFpGetOptimalWinSize(int bitsize)
{
   int w_opt = 1;
   int n_opt = getNumOperations(bitsize, w_opt);
   int w_trial;
   for(w_trial=w_opt+1; w_trial<=IPP_MAX_EXPONENT_NUM; w_trial++) {
      int n_trial = getNumOperations(bitsize, w_trial);
      if(n_trial>=n_opt) break;
      w_opt = w_trial;
      n_opt = n_trial;
   }
   return w_opt;
}


//#define _GRES_DBG_
#if defined(_GRES_DBG_)
#include <stdio.h>
static void printBNU(const char* note, Ipp64u* pData, int len, int nt)
{
   int n, k;

   if(note)
      printf("%s", note);

   for(n=0, k=0; n<len; n++) {
      Ipp64u x = pData[n];
      printf("%016I64x ", x);
      k++;
      if(k==nt) {
         printf("\n");
         k = 0;
      }
   }
   printf("\n");
}
#endif

/* sscm version */
BNU_CHUNK_T* cpGFpxExp(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pE, int nsE,
                     IppsGFpState* pGFpx, Ipp8u* pScratchBuffer)
{
   IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);

   /* remove leding zeros */
   FIX_BNU(pE, nsE);

   {
      Ipp8u* pScratchAligned; /* aligned scratch buffer */
      int nAllocation = 0;    /* points from the pool */

      /* size of element (bytes) */
      int elmDataSize = GFP_FELEN(pGFpx)*sizeof(BNU_CHUNK_T);

      /* exponent bitsize */
      int expBitSize = BITSIZE_BNU(pE, nsE);
      /* optimal size of window */
      int w = (NULL==pScratchBuffer)? 1 : cpGFpGetOptimalWinSize(expBitSize);
      /* number of table entries */
      int nPrecomputed = 1<<w;

      BNU_CHUNK_T* pExpandedE = cpGFpGetPool(1, pGFpx);
      BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGFpx);
      int poolElmLen = GFP_PELEN(pGFpx);

      if(NULL==pScratchBuffer) {
         nAllocation = 2 + div_upper(CACHE_LINE_SIZE, poolElmLen*sizeof(BNU_CHUNK_T));
         pScratchBuffer = (Ipp8u*)cpGFpGetPool(nAllocation, pGFpx);
      }
      pScratchAligned = (Ipp8u*)( IPP_ALIGNED_PTR(pScratchBuffer, CACHE_LINE_SIZE) );

      #if defined(_GRES_DBG_)
      printf("precom tbl:\n");
      #endif
      /* pre-compute auxiliary table t[] = {1, A, A^2, ..., A^(2^w-1)} */
      cpGFpElementCopyPadd(pTmp, GFP_FELEN(pGFpx), MNT_1(GFP_MONT(pBasicGF)), GFP_FELEN(pBasicGF));
      cpScramblePut(pScratchAligned+0, nPrecomputed, (Ipp8u*)pTmp, elmDataSize);
      #if defined(_GRES_DBG_)
      printBNU("precom tbl:\n", pTmp, 48, 6);
      #endif
      {
         int n;
         for(n=1; n<nPrecomputed; n++) {
            pGFpx->mul(pTmp, pTmp, pA, pGFpx);
            cpScramblePut(pScratchAligned+n, nPrecomputed, (Ipp8u*)pTmp, elmDataSize);
            #if defined(_GRES_DBG_)
            printBNU("precom tbl:\n", pTmp, 48, 6);
            #endif
         }
      }

      {
         /* copy exponent value */
         cpGFpElementCopy(pExpandedE, pE, nsE);

         /* expand exponent value */
         ((Ipp32u*)pExpandedE)[BITS2WORD32_SIZE(expBitSize)] = 0;
         expBitSize = ((expBitSize+w-1)/w)*w;

         #if defined(_GRES_DBG_)
         printf("\nexponentiation:\n");
         #endif
         /*
         // exponentiation
         */
         {
            /* digit mask */
            BNU_CHUNK_T dmask = nPrecomputed-1;

            /* position (bit number) of the leftmost window */
            int wPosition = expBitSize-w;

            /* extract leftmost window value */
            Ipp32u eChunk = *((Ipp32u*)((Ipp16u*)pExpandedE+ wPosition/BITSIZE(Ipp16u)));
            int shift = wPosition & 0xF;
            Ipp32u windowVal = (eChunk>>shift) & dmask;

            /* initialize result */
            cpScrambleGet((Ipp8u*)pR, elmDataSize, pScratchAligned+windowVal, nPrecomputed);
            #if defined(_GRES_DBG_)
            printBNU("init result:\n", pR, 48, 6);
            #endif

            for(wPosition-=w; wPosition>=0; wPosition-=w) {
               int k;
               #if defined(_GRES_DBG_)
               printf("\nwPosition=%d\n", wPosition);
               #endif
               /* w times squaring */
               for(k=0; k<w; k++) {
                  pGFpx->sqr(pR, pR, pGFpx);
                  #if defined(_GRES_DBG_)
                  printBNU("sqr:\n", pR, 48, 6);
                  #endif
               }

               /* extract next window value */
               eChunk = *((Ipp32u*)((Ipp16u*)pExpandedE+ wPosition/BITSIZE(Ipp16u)));
               shift = wPosition & 0xF;
               windowVal = (eChunk>>shift) & dmask;

               /* extract value from the pre-computed table */
               cpScrambleGet((Ipp8u*)pTmp, elmDataSize, pScratchAligned+windowVal, nPrecomputed);

               /* and multiply */
               pGFpx->mul(pR, pR, pTmp, pGFpx);
               #if defined(_GRES_DBG_)
               printBNU("mul:\n", pR, 48, 6);
               #endif
            }
         }

      }

      cpGFpReleasePool(nAllocation+2, pGFpx);

      return pR;
   }
}


static void cpPrecomputeMultiExp(Ipp8u* pTable, const BNU_CHUNK_T* ppA[], int nItems, IppsGFpState* pGFpx)
{
   IppsGFpState* pBasicGF = cpGFpBasic(pGFpx);

   int nPrecomputed = 1<<nItems;

   /* length of element (BNU_CHUNK_T) */
   int elmLen = GFP_FELEN(pGFpx);
   /* size of element (bytes) */
   int elmDataSize = GFP_FELEN(pGFpx)*sizeof(BNU_CHUNK_T);

   /* get resource */
   BNU_CHUNK_T* pT = cpGFpGetPool(1, pGFpx);

   /* pTable[0] = 1 */
   cpGFpElementCopyPadd(pT, elmLen, MNT_1(GFP_MONT(pBasicGF)), GFP_FELEN(pBasicGF));
   cpScramblePut(pTable+0, nPrecomputed, (Ipp8u*)pT, elmDataSize);
   /* pTable[1] = A[0] */
   cpScramblePut(pTable+1, nPrecomputed, (Ipp8u*)(ppA[0]), elmDataSize);

   {
      int i, baseIdx;
      for(i=1, baseIdx=2; i<nItems; i++, baseIdx*=2) {
         /* pTable[baseIdx] = A[i] */
         cpScramblePut(pTable+baseIdx, nPrecomputed, (Ipp8u*)(ppA[i]), elmDataSize);

         {
            int nPasses = 1;
            int step = baseIdx/2;

            int k;
            for(k=i-1; k>=0; k--) {
               int tblIdx = baseIdx;

               int n;
               for(n=0; n<nPasses; n++, tblIdx+=2*step) {
                  /* use pre-computed value */
                  cpScrambleGet((Ipp8u*)pT, elmDataSize, pTable+tblIdx, nPrecomputed);
                  pGFpx->mul(pT, pT, ppA[k], pGFpx);
                  cpScramblePut(pTable+tblIdx+step, nPrecomputed, (Ipp8u*)pT, elmDataSize);
               }

               nPasses *= 2;
               step /= 2;
            }
         }
      }
   }

   /* release resourse */
   cpGFpReleasePool(1, pGFpx);
}

static int cpGetMaxBitsizeExponent(const BNU_CHUNK_T* ppE[], int nsE[], int nItems)
{
   int n;
   /* find out the longest exponent */
   int expBitSize = BITSIZE_BNU(ppE[0], nsE[0]);
   for(n=1; n<nItems; n++) {
      expBitSize = IPP_MAX(expBitSize, BITSIZE_BNU(ppE[n], nsE[n]));
   }
   return expBitSize;
}

static int GetIndex(const BNU_CHUNK_T* ppE[], int nItems, int nBit)
{
   int shift = nBit%BYTESIZE;
   int offset= nBit/BYTESIZE;
   int index = 0;

   int n;
   for(n=nItems; n>0; n--) {
      const Ipp8u* pE = ((Ipp8u*)ppE[n-1]) + offset;
      Ipp8u e = pE[0];
      index <<= 1;
      index += (e>>shift) &1;
   }
   return index;
}

/* sscm version */
BNU_CHUNK_T* cpGFpxMultiExp(BNU_CHUNK_T* pR, const BNU_CHUNK_T* ppA[], const BNU_CHUNK_T* ppE[], int nsE[], int nItems,
                          IppsGFpState* pGFpx, Ipp8u* pScratchBuffer)
{
   /* align scratch buffer */
   pScratchBuffer = (Ipp8u*)( IPP_ALIGNED_PTR(pScratchBuffer, CACHE_LINE_SIZE) );
   /* pre-compute table */
   cpPrecomputeMultiExp(pScratchBuffer, ppA, nItems, pGFpx);

   {
      /* find out the longest exponent */
      int expBitSize = cpGetMaxBitsizeExponent(ppE, nsE, nItems);

      /* allocate resource and copy expanded exponents into */
      const BNU_CHUNK_T* ppExponent[IPP_MAX_EXPONENT_NUM];
      {
         int n;
         for(n=0; n<nItems; n++) {
            BNU_CHUNK_T* pData = cpGFpGetPool(1, pGFpx);
            cpGFpElementCopyPadd(pData, GFP_FELEN(pGFpx), ppE[n], nsE[n]);
            ppExponent[n] = pData;
         }
      }

      /* multiexponentiation */
      {
         int nPrecomputed = 1<<nItems;
         int elmDataSize = GFP_FELEN(pGFpx)*sizeof(BNU_CHUNK_T);

         /* get temporary */
         BNU_CHUNK_T* pT = cpGFpGetPool(1, pGFpx);

         /* init result */
         int tblIdx = GetIndex(ppExponent, nItems, --expBitSize);
         cpScrambleGet((Ipp8u*)pR, elmDataSize, pScratchBuffer+tblIdx, nPrecomputed);

         /* compute the rest: square and multiply */
         for(--expBitSize; expBitSize>=0; expBitSize--) {
            pGFpx->sqr(pR, pR, pGFpx);
            tblIdx = GetIndex(ppExponent, nItems, expBitSize);
            cpScrambleGet((Ipp8u*)pT, elmDataSize, pScratchBuffer+tblIdx, nPrecomputed);
            pGFpx->mul(pR, pR, pT, pGFpx);
         }

         /* release resourse */
         cpGFpReleasePool(1, pGFpx);
      }

      /* release resourse */
      cpGFpReleasePool(nItems, pGFpx);

      return pR;
   }
}

#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
