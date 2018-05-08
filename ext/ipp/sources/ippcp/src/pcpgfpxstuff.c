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
//     Internal operations over GF(p) extension.
// 
//     Context:
//        cpGFpxRand
//        cpGFpxSet, cpGFpxSetPolyTerm
//        cpGFpxGet, cpGFpxGetPolyTerm
// 
//        cpGFpxNeg
//        cpGFpxInv
//        cpGFpxHalve
//        cpGFpxAdd, cpGFpxAdd_GFE
//        cpGFpxSub, cpGFpxSub_GFE
//        cpGFpxMul, cpGFpxMul_GFE
//        cpGFpxSqr
//        cpGFpxExp, cpGFpxMultiExp
//        cpGFpxConj
// 
// 
*/
#include "owncp.h"

#include "pcpbnumisc.h"
#include "pcpgfpxstuff.h"
#include "gsscramble.h"

//gres: temporary excluded: #include <assert.h>


BNU_CHUNK_T* cpGFpxRand(BNU_CHUNK_T* pR, gsModEngine* pGFEx, IppBitSupplier rndFunc, void* pRndParam)
{
   if( GFP_IS_BASIC(pGFEx) )
      return cpGFpRand(pR, pGFEx, rndFunc, pRndParam);

   else {
      gsModEngine* pBasicGFE = cpGFpBasic(pGFEx);
      int basicElemLen = GFP_FELEN(pBasicGFE);
      int basicDeg = cpGFpBasicDegreeExtension(pGFEx);

      BNU_CHUNK_T* pTmp = pR;
      int deg;
      for(deg=0; deg<basicDeg; deg++) {
         if(NULL == cpGFpRand(pTmp, pBasicGFE, rndFunc, pRndParam))
            break;
         pTmp += basicElemLen;
      }
      return deg==basicDeg? pR : NULL;
   }
}

BNU_CHUNK_T* cpGFpxSet(BNU_CHUNK_T* pE, const BNU_CHUNK_T* pDataA, int nsA, gsModEngine* pGFEx)
{
   if( GFP_IS_BASIC(pGFEx) )
      return cpGFpSet(pE, pDataA, nsA, pGFEx);

   else {
      gsModEngine* pBasicGFE = cpGFpBasic(pGFEx);
      int basicElemLen = GFP_FELEN(pBasicGFE);

      BNU_CHUNK_T* pTmpE = pE;
      int basicDeg = cpGFpBasicDegreeExtension(pGFEx);

      int deg, error;
      for(deg=0, error=0; deg<basicDeg && !error; deg++) {
         int pieceA = IPP_MIN(nsA, basicElemLen);

         error = NULL == cpGFpSet(pTmpE, pDataA, pieceA, pBasicGFE);
         pTmpE   += basicElemLen;
         pDataA += pieceA;
         nsA -= pieceA;
      }

      return (deg<basicDeg)? NULL : pE;
   }
}

BNU_CHUNK_T* cpGFpxSetPolyTerm(BNU_CHUNK_T* pE, int deg, const BNU_CHUNK_T* pDataA, int nsA, gsModEngine* pGFEx)
{
   pE += deg * GFP_FELEN(pGFEx);
   return cpGFpxSet(pE, pDataA, nsA, pGFEx);
}

BNU_CHUNK_T* cpGFpxGet(BNU_CHUNK_T* pDataA, int nsA, const BNU_CHUNK_T* pE, gsModEngine* pGFEx)
{
   cpGFpElementPadd(pDataA, nsA, 0);

   if( GFP_IS_BASIC(pGFEx) )
      return cpGFpGet(pDataA, nsA, pE, pGFEx);

   else {
      gsModEngine* pBasicGFE = cpGFpBasic(pGFEx);
      int basicElemLen = GFP_FELEN(pBasicGFE);

      BNU_CHUNK_T* pTmp = pDataA;
      int basicDeg = cpGFpBasicDegreeExtension(pGFEx);

      int deg;
      for(deg=0; deg<basicDeg && nsA>0; deg++) {
         int pieceA = IPP_MIN(nsA, basicElemLen);

         cpGFpGet(pTmp, pieceA, pE, pBasicGFE);
         pE   += basicElemLen;
         pTmp += pieceA;
         nsA -= pieceA;
      }

      return pDataA;
   }
}

BNU_CHUNK_T* cpGFpxGetPolyTerm(BNU_CHUNK_T* pDataA, int nsA, const BNU_CHUNK_T* pE, int deg, gsModEngine* pGFEx)
{
   pE += deg * GFP_FELEN(pGFEx);
   return cpGFpxGet(pDataA, nsA, pE, pGFEx);
}

BNU_CHUNK_T* cpGFpxConj(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsModEngine* pGFEx)
{
   gsModEngine* pGroundGFE = GFP_PARENT(pGFEx);
   int groundElemLen = GFP_FELEN(pGroundGFE);

   if(pR != pA)
      cpGFpElementCopy(pR, pA, groundElemLen);
   MOD_METHOD(pGroundGFE)->neg(pR+groundElemLen, pA+groundElemLen, pGroundGFE);

   return pR;
}


BNU_CHUNK_T* cpGFpxAdd_GFE(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pGroundB, gsModEngine* pGFEx)
{
   gsModEngine* pGroundGFE = GFP_PARENT(pGFEx);
   mod_add addF = MOD_METHOD(pGroundGFE)->add;

   if(pR != pA) {
      int groundElemLen = GFP_FELEN(pGroundGFE);
      int deg = GFP_EXTDEGREE(pGFEx);
      cpGFpElementCopy(pR+groundElemLen, pA+groundElemLen, groundElemLen*(deg-1));
   }
   return addF(pR, pA, pGroundB, pGroundGFE);
}

BNU_CHUNK_T* cpGFpxSub_GFE(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pGroundB, gsModEngine* pGFEx)
{
   gsModEngine* pGroundGFE = GFP_PARENT(pGFEx);
   mod_sub subF = MOD_METHOD(pGroundGFE)->sub;

   if(pR != pA) {
      int groundElemLen = GFP_FELEN(pGroundGFE);
      int deg = GFP_EXTDEGREE(pGFEx);
      cpGFpElementCopy(pR+groundElemLen, pA+groundElemLen, groundElemLen*(deg-1));
   }
   return subF(pR, pA, pGroundB, pGroundGFE);
}

BNU_CHUNK_T* cpGFpxMul_GFE(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, const BNU_CHUNK_T* pGroundB, gsModEngine* pGFEx)
{
   gsModEngine* pGroundGFE = GFP_PARENT(pGFEx);
   mod_mul mulF = MOD_METHOD(pGroundGFE)->mul;

   int grounfElemLen = GFP_FELEN(pGroundGFE);

   BNU_CHUNK_T* pTmp = pR;

   int deg;
   for(deg=0; deg<GFP_EXTDEGREE(pGFEx); deg++) {
      mulF(pTmp, pA, pGroundB, pGroundGFE);
      pTmp += grounfElemLen;
      pA += grounfElemLen;
   }
   return pR;
}

BNU_CHUNK_T* cpGFpxNeg(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsModEngine* pGFEx)
{
   gsModEngine* pBasicGFE = cpGFpBasic(pGFEx);
   int basicElemLen = GFP_FELEN(pBasicGFE);
   int basicDeg = cpGFpBasicDegreeExtension(pGFEx);

   BNU_CHUNK_T* pTmp = pR;
   int deg;
   for(deg=0; deg<basicDeg; deg++) {
      GFP_METHOD(pBasicGFE)->neg(pTmp, pA, pBasicGFE);
      pTmp += basicElemLen;
      pA += basicElemLen;
   }
   return pR;
}

static BNU_CHUNK_T* gfpxPolyDiv(BNU_CHUNK_T* pQ, BNU_CHUNK_T* pR,
                        const BNU_CHUNK_T* pA,
                        const BNU_CHUNK_T* pB,
                        gsModEngine* pGFEx)
{
   if( GFP_IS_BASIC(pGFEx) )
      return NULL;

   else {
      int elemLen = GFP_FELEN(pGFEx);
      gsModEngine* pGroundGFE = GFP_PARENT(pGFEx);
      int termLen = GFP_FELEN(pGroundGFE);

      int degA = degree(pA, pGFEx);
      int degB = degree(pB, pGFEx);

      if(degB==0) {
         if( GFP_IS_ZERO(pB, termLen) )
            return NULL;
         else {
            gsModEngine* pBasicGFE = cpGFpBasic(pGroundGFE);

            cpGFpInv(pR, pB, pBasicGFE);
            cpGFpElementPadd(pR+GFP_FELEN(pGroundGFE), termLen-GFP_FELEN(pGroundGFE), 0);
            cpGFpxMul_GFE(pQ, pA, pR, pGFEx);
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
         mod_mul mulF = GFP_METHOD(pGroundGFE)->mul;
         mod_sub subF = GFP_METHOD(pGroundGFE)->sub;

         int i, j;
         BNU_CHUNK_T* pProduct = cpGFpGetPool(2, pGroundGFE);
         BNU_CHUNK_T* pInvB = pProduct + GFP_PELEN(pGroundGFE);
         //gres: temporary excluded: assert(NULL!=pProduct);

         cpGFpElementCopyPadd(pR, elemLen, pA, (degA+1)*termLen);
         cpGFpElementPadd(pQ, elemLen, 0);

         cpGFpxInv(pInvB, GFPX_IDX_ELEMENT(pB, degB, termLen), pGroundGFE);

         for(i=0; i<=degA-degB && !GFP_IS_ZERO(GFPX_IDX_ELEMENT(pR, degA-i, termLen), termLen); i++) {
            /* compute q term */
            mulF(GFPX_IDX_ELEMENT(pQ, degA-degB-i, termLen),
                 GFPX_IDX_ELEMENT(pR, degA-i, termLen),
                 pInvB,
                 pGroundGFE);

            /* R -= B * q */
            cpGFpElementPadd(GFPX_IDX_ELEMENT(pR, degA-i, termLen), termLen, 0);
            for(j=0; j<degB; j++) {
               mulF(pProduct,
                    GFPX_IDX_ELEMENT(pB, j ,termLen),
                    GFPX_IDX_ELEMENT(pQ, degA-degB-i, termLen),
                    pGroundGFE);
               subF(GFPX_IDX_ELEMENT(pR, degA-degB-i+j, termLen),
                    GFPX_IDX_ELEMENT(pR, degA-degB-i+j, termLen),
                    pProduct,
                    pGroundGFE);
            }
         }

         cpGFpReleasePool(2, pGroundGFE);
         return pR;
      }
   }
}

static BNU_CHUNK_T* gfpxGeneratorDiv(BNU_CHUNK_T* pQ, BNU_CHUNK_T* pR, const BNU_CHUNK_T* pB, gsModEngine* pGFEx)
{
   if( GFP_IS_BASIC(pGFEx) )
      return NULL;

   else {
      int elemLen = GFP_FELEN(pGFEx);

      gsModEngine* pGroundGFE = GFP_PARENT(pGFEx);
      mod_mul mulF = GFP_METHOD(pGroundGFE)->mul;
      mod_sub subF = GFP_METHOD(pGroundGFE)->sub;

      int termLen = GFP_FELEN(pGroundGFE);

      BNU_CHUNK_T* pInvB = cpGFpGetPool(2, pGroundGFE);
      BNU_CHUNK_T* pTmp  = pInvB + GFP_PELEN(pGroundGFE);

      int degB = degree(pB, pGFEx);
      int i;

      //gres: temporary excluded: assert(NULL!=pInvB);

      cpGFpElementCopy(pR, GFP_MODULUS(pGFEx), elemLen);
      cpGFpElementPadd(pQ, elemLen, 0);

      cpGFpxInv(pInvB, GFPX_IDX_ELEMENT(pB, degB, termLen), pGroundGFE);

      for(i=0; i<degB; i++) {
         BNU_CHUNK_T* ptr;
         mulF(pTmp, pInvB, GFPX_IDX_ELEMENT(pB, i, termLen), pGroundGFE);
         ptr = GFPX_IDX_ELEMENT(pR, GFP_EXTDEGREE(pGFEx)-degB+i, termLen);
         subF(ptr, ptr, pTmp, pGroundGFE);
      }

      gfpxPolyDiv(pQ, pR, pR, pB, pGFEx);

      cpGFpElementCopy(GFPX_IDX_ELEMENT(pQ, GFP_EXTDEGREE(pGFEx)-degB, termLen), pInvB, termLen);

      cpGFpReleasePool(2, pGroundGFE);
      return pR;
   }
}

BNU_CHUNK_T* cpGFpxInv(BNU_CHUNK_T* pR, const BNU_CHUNK_T* pA, gsModEngine* pGFEx)
{
   if( GFP_IS_BASIC(pGFEx) )
      return cpGFpInv(pR, pA, pGFEx);

   if(0==degree(pA, pGFEx)) {
      gsModEngine* pGroundGFE = GFP_PARENT(pGFEx);
      BNU_CHUNK_T* tmpR = cpGFpGetPool(1, pGroundGFE);
      //gres: temporary excluded: assert(NULL!=tmpR);

      cpGFpxInv(tmpR, pA, pGroundGFE);

      cpGFpElementCopyPadd(pR, GFP_FELEN(pGFEx), tmpR, GFP_FELEN(pGroundGFE));
      cpGFpReleasePool(1, pGroundGFE);
      return pR;
   }

   else {
      int elemLen = GFP_FELEN(pGFEx);
      gsModEngine* pGroundGFE = GFP_PARENT(pGFEx);
      gsModEngine* pBasicGFE = cpGFpBasic(pGFEx);

      int pxVars = 6;
      int pelemLen = GFP_PELEN(pGFEx);
      BNU_CHUNK_T* lastrem = cpGFpGetPool(pxVars, pGFEx);
      BNU_CHUNK_T* rem     = lastrem + pelemLen;
      BNU_CHUNK_T* quo     = rem +  pelemLen;
      BNU_CHUNK_T* lastaux = quo + pelemLen;
      BNU_CHUNK_T* aux     = lastaux + pelemLen;
      BNU_CHUNK_T* temp    = aux + pelemLen;
      //gres: temporary excluded: assert(NULL!=lastrem);

      cpGFpElementCopy(lastrem, pA, elemLen);
      cpGFpElementCopyPadd(lastaux, elemLen, GFP_MNT_R(pBasicGFE), GFP_FELEN(pBasicGFE));

      gfpxGeneratorDiv(quo, rem, pA, pGFEx);
      cpGFpxNeg(aux, quo, pGFEx);

      while(degree(rem, pGFEx) > 0) {
         gfpxPolyDiv(quo, temp, lastrem, rem, pGFEx);
         SWAP_PTR(BNU_CHUNK_T, rem, lastrem); //
         SWAP_PTR(BNU_CHUNK_T, temp, rem);

         GFP_METHOD(pGFEx)->neg(quo, quo, pGFEx);
         GFP_METHOD(pGFEx)->mul(temp, quo, aux, pGFEx);
         GFP_METHOD(pGFEx)->add(temp, lastaux, temp, pGFEx);
         SWAP_PTR(BNU_CHUNK_T, aux, lastaux);
         SWAP_PTR(BNU_CHUNK_T, temp, aux);
      }
      if (GFP_IS_ZERO(rem, elemLen)) { /* gcd != 1 */
         cpGFpReleasePool(pxVars, pGFEx);
         return NULL;
      }

      {
         BNU_CHUNK_T* invRem  = cpGFpGetPool(1, pGroundGFE);
         //gres: temporary excluded: assert(NULL!=invRem);

         cpGFpxInv(invRem, rem, pGroundGFE);
         cpGFpxMul_GFE(pR, aux, invRem, pGFEx);

         cpGFpReleasePool(1, pGroundGFE);
      }

      cpGFpReleasePool(pxVars, pGFEx);

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
                     gsModEngine* pGFEx, Ipp8u* pScratchBuffer)
{
   gsModEngine* pBasicGFE = cpGFpBasic(pGFEx);

   /* remove leding zeros */
   FIX_BNU(pE, nsE);

   {
      mod_mul mulF = GFP_METHOD(pGFEx)->mul;  /* mul and sqr methods */
      mod_sqr sqrF = GFP_METHOD(pGFEx)->sqr;

      BNU_CHUNK_T* pScratchAligned; /* aligned scratch buffer */
      int nAllocation = 0;    /* points from the pool */

      /* size of element */
      int elmLen = GFP_FELEN(pGFEx);

      /* exponent bitsize */
      int expBitSize = BITSIZE_BNU(pE, nsE);
      /* optimal size of window */
      int w = (NULL==pScratchBuffer)? 1 : cpGFpGetOptimalWinSize(expBitSize);
      /* number of table entries */
      int nPrecomputed = 1<<w;

      int poolElmLen = GFP_PELEN(pGFEx);
      BNU_CHUNK_T* pExpandedE = cpGFpGetPool(1, pGFEx);
      BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGFEx);
      //gres: temporary excluded: assert(NULL!=pExpandedE && NULL!=pTmp);

      if(NULL==pScratchBuffer) {
         nAllocation = 2 + div_upper(CACHE_LINE_SIZE, poolElmLen*sizeof(BNU_CHUNK_T));
         pScratchBuffer = (Ipp8u*)cpGFpGetPool(nAllocation, pGFEx);
         //gres: temporary excluded: assert(NULL!=pScratchBuffer);
      }
      pScratchAligned = (BNU_CHUNK_T*)( IPP_ALIGNED_PTR(pScratchBuffer, CACHE_LINE_SIZE) );

      #if defined(_GRES_DBG_)
      printf("precom tbl:\n");
      #endif
      /* pre-compute auxiliary table t[] = {A^0, A^1, A^2, ..., A^(2^w-1)} */
      cpGFpElementCopyPadd(pTmp, elmLen, GFP_MNT_R(pBasicGFE), GFP_FELEN(pBasicGFE));
      //cpScramblePut(pScratchAligned+0, nPrecomputed, (Ipp8u*)pTmp, elmDataSize);
      gsScramblePut(pScratchAligned, 0, pTmp, elmLen, w);
      #if defined(_GRES_DBG_)
      printBNU("precom tbl:\n", pTmp, 48, 6);
      #endif

      { /* pre compute multiplication table */
         int n;
         for(n=1; n<nPrecomputed; n++) {
            mulF(pTmp, pTmp, pA, pGFEx);
            //cpScramblePut(pScratchAligned+n, nPrecomputed, (Ipp8u*)pTmp, elmDataSize);
            gsScramblePut(pScratchAligned, n, pTmp, elmLen, w);
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
            //cpScrambleGet((Ipp8u*)pR, elmDataSize, pScratchAligned+windowVal, nPrecomputed);
            gsScrambleGet_sscm(pR, elmLen, pScratchAligned, windowVal, w);
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
                  sqrF(pR, pR, pGFEx);
                  #if defined(_GRES_DBG_)
                  printBNU("sqr:\n", pR, 48, 6);
                  #endif
               }

               /* extract next window value */
               eChunk = *((Ipp32u*)((Ipp16u*)pExpandedE+ wPosition/BITSIZE(Ipp16u)));
               shift = wPosition & 0xF;
               windowVal = (eChunk>>shift) & dmask;

               /* extract value from the pre-computed table */
               //cpScrambleGet((Ipp8u*)pTmp, elmDataSize, pScratchAligned+windowVal, nPrecomputed);
               gsScrambleGet_sscm(pTmp, elmLen, pScratchAligned, windowVal, w);

               /* and multiply */
               mulF(pR, pR, pTmp, pGFEx);
               #if defined(_GRES_DBG_)
               printBNU("mul:\n", pR, 48, 6);
               #endif
            }
         }

      }

      cpGFpReleasePool(nAllocation+2, pGFEx);

      return pR;
   }
}

static void cpPrecomputeMultiExp(BNU_CHUNK_T* pTable, const BNU_CHUNK_T* ppA[], int nItems, gsModEngine* pGFEx)
{
   gsModEngine* pBasicGFE = cpGFpBasic(pGFEx);

   //int nPrecomputed = 1<<nItems;

   /* length of element (BNU_CHUNK_T) */
   int elmLen = GFP_FELEN(pGFEx);

   /* get resource */
   BNU_CHUNK_T* pT = cpGFpGetPool(1, pGFEx);
   //gres: temporary excluded: assert(NULL!=pT);

   /* pTable[0] = 1 */
   cpGFpElementCopyPadd(pT, elmLen, GFP_MNT_R(pBasicGFE), GFP_FELEN(pBasicGFE));
   //cpScramblePut(pTable+0, nPrecomputed, (Ipp8u*)pT, elmDataSize);
   gsScramblePut(pTable, 0, pT, elmLen, nItems);
   /* pTable[1] = A[0] */
   //cpScramblePut(pTable+1, nPrecomputed, (Ipp8u*)(ppA[0]), elmDataSize);
   gsScramblePut(pTable, 1, ppA[0], elmLen, nItems);

   {
      mod_mul mulF = GFP_METHOD(pGFEx)->mul;  /* mul method */

      int i, baseIdx;
      for(i=1, baseIdx=2; i<nItems; i++, baseIdx*=2) {
         /* pTable[baseIdx] = A[i] */
         //cpScramblePut(pTable+baseIdx, nPrecomputed, (Ipp8u*)(ppA[i]), elmDataSize);
         gsScramblePut(pTable, baseIdx, ppA[i], elmLen, nItems);

         {
            int nPasses = 1;
            int step = baseIdx/2;

            int k;
            for(k=i-1; k>=0; k--) {
               int tblIdx = baseIdx;

               int n;
               for(n=0; n<nPasses; n++, tblIdx+=2*step) {
                  /* use pre-computed value */
                  //cpScrambleGet((Ipp8u*)pT, elmDataSize, pTable+tblIdx, nPrecomputed);
                  gsScrambleGet(pT, elmLen, pTable, tblIdx, nItems);
                  mulF(pT, pT, ppA[k], pGFEx);
                  //cpScramblePut(pTable+tblIdx+step, nPrecomputed, (Ipp8u*)pT, elmDataSize);
                  gsScramblePut(pTable, tblIdx+step, pT, elmLen, nItems);
               }

               nPasses *= 2;
               step /= 2;
            }
         }
      }
   }

   /* release resourse */
   cpGFpReleasePool(1, pGFEx);
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
                          gsModEngine* pGFEx, Ipp8u* pScratchBuffer)
{
   /* align scratch buffer */
   BNU_CHUNK_T* pTable = (BNU_CHUNK_T*)( IPP_ALIGNED_PTR(pScratchBuffer, CACHE_LINE_SIZE) );
   /* pre-compute table */
   cpPrecomputeMultiExp(pTable, ppA, nItems, pGFEx);

   {
      mod_mul mulF = GFP_METHOD(pGFEx)->mul;  /* mul and sqr methods and parameter */
      mod_sqr sqrF = GFP_METHOD(pGFEx)->sqr;
      int elmLen = GFP_FELEN(pGFEx);

      /* find out the longest exponent */
      int expBitSize = cpGetMaxBitsizeExponent(ppE, nsE, nItems);

      /* allocate resource and copy expanded exponents into */
      const BNU_CHUNK_T* ppExponent[IPP_MAX_EXPONENT_NUM];
      {
         int n;
         for(n=0; n<nItems; n++) {
            BNU_CHUNK_T* pData = cpGFpGetPool(1, pGFEx);
            //gres: temporary excluded: assert(NULL!=pData);
            cpGFpElementCopyPadd(pData, elmLen, ppE[n], nsE[n]);
            ppExponent[n] = pData;
         }
      }

      /* multiexponentiation */
      {
         /* get temporary */
         BNU_CHUNK_T* pT = cpGFpGetPool(1, pGFEx);

         /* init result */
         int tblIdx = GetIndex(ppExponent, nItems, --expBitSize);
         //cpScrambleGet((Ipp8u*)pR, elmDataSize, pScratchBuffer+tblIdx, nPrecomputed);
         gsScrambleGet_sscm(pR, elmLen, pTable, tblIdx, nItems);

         //gres: temporary excluded: assert(NULL!=pT);

         /* compute the rest: square and multiply */
         for(--expBitSize; expBitSize>=0; expBitSize--) {
            sqrF(pR, pR, pGFEx);
            tblIdx = GetIndex(ppExponent, nItems, expBitSize);
            //cpScrambleGet((Ipp8u*)pT, elmDataSize, pScratchBuffer+tblIdx, nPrecomputed);
            gsScrambleGet_sscm(pT, elmLen, pTable, tblIdx, nItems);
            mulF(pR, pR, pT, pGFEx);
         }

         /* release resourse */
         cpGFpReleasePool(1, pGFEx);
      }

      /* release resourse */
      cpGFpReleasePool(nItems, pGFEx);

      return pR;
   }
}
