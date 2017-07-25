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
//     EC over GF(p^m) definitinons
// 
//     Context:
//        ippsGFpECGetSize()
//        ippsGFpECInit()
// 
//        ippsGFpECSet()
//        ippsGFpECSetSubgroup()
//
//        ippsGFpECGet()
//        ippsGFpECGetSubgroup()
//
//        ippsGFpECScratchBufferSize()
//        ippsGFpECVerify()
// 
// 
*/
#include "owndefs.h"
#include "owncp.h"

#include "pcpgfpecstuff.h"

int cpGFpECGetSize(int basicDeg, int basicElmBitSize)
{
   int ctxSize = 0;
   int elemLen = basicDeg*BITS_BNU_CHUNK(basicElmBitSize);

   int maxOrderBits = 1+ basicDeg*basicElmBitSize;
   int maxOrderLen32 = BITS2WORD32_SIZE(maxOrderBits);
   #if defined(_LEGACY_ECCP_SUPPORT_)
   int maxOrderLen = BITS_BNU_CHUNK(maxOrderBits);
   #endif

   int montgomeryCtxSize;
   if(ippStsNoErr==ippsMontGetSize(ippBinaryMethod, maxOrderLen32, &montgomeryCtxSize)) {
      montgomeryCtxSize -= MONT_ALIGNMENT-1;

      ctxSize = sizeof(IppsGFpECState)
               +elemLen*sizeof(BNU_CHUNK_T)    /* EC coeff    A */
               +elemLen*sizeof(BNU_CHUNK_T)    /* EC coeff    B */
               +elemLen*sizeof(BNU_CHUNK_T)    /* generator G.x */
               +elemLen*sizeof(BNU_CHUNK_T)    /* generator G.y */
               +elemLen*sizeof(BNU_CHUNK_T)    /* generator G.z */
               +montgomeryCtxSize              /* mont engine (R) */
               +elemLen*sizeof(BNU_CHUNK_T)    /* cofactor */
               #if defined(_LEGACY_ECCP_SUPPORT_)
               +2*elemLen*3*sizeof(BNU_CHUNK_T)    /* regular and ephemeral public  keys */
               +2*maxOrderLen*sizeof(BNU_CHUNK_T)  /* regular and ephemeral private keys */
               #endif
               +elemLen*sizeof(BNU_CHUNK_T)*3*EC_POOL_SIZE;
   }
   return ctxSize;
}

IPPFUN(IppStatus, ippsGFpECGetSize,(const IppsGFpState* pGF, int* pCtxSizeInBytes))
{
   IPP_BAD_PTR2_RET(pGF, pCtxSizeInBytes);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   *pCtxSizeInBytes = cpGFpECGetSize(cpGFpBasicDegreeExtension(pGF), GFP_FEBITLEN(cpGFpBasic(pGF)))
                     +ECGFP_ALIGNMENT;
   return ippStsNoErr;
}


IPPFUN(IppStatus, ippsGFpECInit,(const IppsGFpState* pGF,
                                 const IppsGFpElement* pA, const IppsGFpElement* pB,
                                 IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pGF, pEC);

   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );

   {
      Ipp8u* ptr = (Ipp8u*)pEC;

      int elemLen = GFP_FELEN(pGF);

      int maxOrderBits = 1+ cpGFpBasicDegreeExtension(pGF) * GFP_FEBITLEN(cpGFpBasic(pGF));
      int maxOrderLen32 = BITS2WORD32_SIZE(maxOrderBits);
      #if defined(_LEGACY_ECCP_SUPPORT_)
      int maxOrdLen = BITS_BNU_CHUNK(maxOrderBits);
      #endif

      int montgomeryCtxSize;
      ippsMontGetSize(ippBinaryMethod, maxOrderLen32, &montgomeryCtxSize);
      montgomeryCtxSize -= MONT_ALIGNMENT-1;

      ECP_ID(pEC) = idCtxGFPEC;
      ECP_GFP(pEC) = (IppsGFpState*)(IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT));
      ECP_POINTLEN(pEC) = elemLen*3;
      ECP_ORDBITSIZE(pEC) = maxOrderBits;
      ECP_SPECIFIC(pEC) = ECP_ARB;

      ptr += sizeof(IppsGFpECState);
      ECP_A(pEC) = (BNU_CHUNK_T*)(ptr);  ptr += elemLen*sizeof(BNU_CHUNK_T);
      ECP_B(pEC) = (BNU_CHUNK_T*)(ptr);  ptr += elemLen*sizeof(BNU_CHUNK_T);
      ECP_G(pEC) = (BNU_CHUNK_T*)(ptr);  ptr += ECP_POINTLEN(pEC)*sizeof(BNU_CHUNK_T);
      ECP_PREMULBP(pEC) = (cpPrecompAP*)NULL;
      ECP_MONT_R(pEC) = (IppsMontState*)( IPP_ALIGNED_PTR((ptr), (MONT_ALIGNMENT)) ); ptr += montgomeryCtxSize;
      ECP_COFACTOR(pEC) = (BNU_CHUNK_T*)(ptr); ptr += elemLen*sizeof(BNU_CHUNK_T);
      #if defined(_LEGACY_ECCP_SUPPORT_)
      ECP_PUBLIC(pEC)   = (BNU_CHUNK_T*)(ptr); ptr += 3*elemLen*sizeof(BNU_CHUNK_T);
      ECP_PUBLIC_E(pEC) = (BNU_CHUNK_T*)(ptr); ptr += 3*elemLen*sizeof(BNU_CHUNK_T);
      ECP_PRIVAT(pEC)   = (BNU_CHUNK_T*)(ptr); ptr += maxOrdLen*sizeof(BNU_CHUNK_T);
      ECP_PRIVAT_E(pEC) = (BNU_CHUNK_T*)(ptr); ptr += maxOrdLen*sizeof(BNU_CHUNK_T);
      ECP_SBUFFER(pEC) = (BNU_CHUNK_T*)0;
      #endif
      ECP_POOL(pEC) = (BNU_CHUNK_T*)(ptr);  //ptr += ECP_POINTLEN(pEC)*sizeof(BNU_CHUNK_T)*EC_POOL_SIZE;

      cpGFpElementPadd(ECP_A(pEC), elemLen, 0);
      cpGFpElementPadd(ECP_B(pEC), elemLen, 0);
      cpGFpElementPadd(ECP_G(pEC), elemLen*3, 0);
      ippsMontInit(ippBinaryMethod, maxOrderLen32, ECP_MONT_R(pEC));
      cpGFpElementPadd(ECP_COFACTOR(pEC), elemLen, 0);

      cpGFpElementPadd(ECP_POOL(pEC), elemLen*3*EC_POOL_SIZE, 0);

      /* set up EC if possible */
      if(pA && pB)
         return ippsGFpECSet(pA,pB, pEC);
      else
         return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECSet,(const IppsGFpElement* pA,
                                const IppsGFpElement* pB,
                                IppsGFpECState* pEC))
{
   IPP_BAD_PTR1_RET(pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );

   IPP_BAD_PTR2_RET(pA, pB);
   IPP_BADARG_RET( !GFPE_TEST_ID(pA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pB), ippStsContextMatchErr );
      
   IPP_BADARG_RET( GFPE_ROOM(pA)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( GFPE_ROOM(pB)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   {
      IppsGFpState* pGF = ECP_GFP(pEC);
      int elemLen = GFP_FELEN(pGF);

      /* copy A */
      cpGFpElementPadd(ECP_A(pEC), elemLen, 0);
      cpGFpElementCopy(ECP_A(pEC), GFPE_DATA(pA), elemLen);
      /* and set up A-specific (a==0 or a==-3) if is */
      if(GFP_IS_ZERO(ECP_A(pEC), elemLen))
         ECP_SPECIFIC(pEC) = ECP_EPID2;

      cpGFpElementSetChunk(ECP_B(pEC), elemLen, 3);
      pGF->encode(ECP_B(pEC), ECP_B(pEC), pGF);
      pGF->add(ECP_B(pEC), ECP_A(pEC), ECP_B(pEC), pGF);
      if(GFP_IS_ZERO(ECP_B(pEC), elemLen))
         ECP_SPECIFIC(pEC) = ECP_STD;

      /* copy B */
      cpGFpElementPadd(ECP_B(pEC), elemLen, 0);
      cpGFpElementCopy(ECP_B(pEC), GFPE_DATA(pB), elemLen);
      /* and set type of affine infinity representation:
      // (0,1) if B==0
      // (0,0) if B!=0 */
      ECP_INFINITY(pEC) = GFP_IS_ZERO(ECP_B(pEC), elemLen);

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECSetSubgroup,(const IppsGFpElement* pX, const IppsGFpElement* pY,
                                        const IppsBigNumState* pOrder,
                                        const IppsBigNumState* pCofactor,
                                        IppsGFpECState* pEC))
{
   IPP_BAD_PTR1_RET(pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );

   IPP_BAD_PTR2_RET(pX, pY);
   IPP_BADARG_RET( !GFPE_TEST_ID(pX), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pY), ippStsContextMatchErr );
   IPP_BADARG_RET( GFPE_ROOM(pX)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( GFPE_ROOM(pY)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);

   IPP_BAD_PTR2_RET(pOrder, pCofactor);
   pOrder = (IppsBigNumState*)( IPP_ALIGNED_PTR(pOrder, BN_ALIGNMENT) );
   IPP_BADARG_RET(!BN_VALID_ID(pOrder), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_SIGN(pOrder)!= IppsBigNumPOS, ippStsBadArgErr);

   pCofactor = (IppsBigNumState*)( IPP_ALIGNED_PTR(pCofactor, BN_ALIGNMENT) );
   IPP_BADARG_RET(!BN_VALID_ID(pCofactor), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_SIGN(pCofactor)!= IppsBigNumPOS, ippStsBadArgErr);

   {
      IppsGFpState* pGF = ECP_GFP(pEC);
      int elemLen = GFP_FELEN(pGF);

#if 0
      /* set base point at infinity */
      cpGFpElementPadd(ECP_G(pEC), elemLen*3, 0);
      if(!GFP_IS_ZERO(GFPE_DATA(pX), elemLen) || !GFP_IS_ZERO(GFPE_DATA(pY), elemLen)) {
         /* reset base point as infine */
         cpGFpElementCopy(ECP_G(pEC), GFPE_DATA(pX), elemLen);
         cpGFpElementCopy(ECP_G(pEC)+elemLen, GFPE_DATA(pY), elemLen);
         cpGFpElementCopyPadd(ECP_G(pEC)+elemLen*2, elemLen, MNT_1(GFP_MONT(cpGFpBasic(pGF))), GFP_FELEN(cpGFpBasic(pGF)));
      }
#endif
      gfec_SetPoint(ECP_G(pEC), GFPE_DATA(pX), GFPE_DATA(pY), pEC);

      {
      ///int maxOrderBits = 1+ cpGFpBasicDegreeExtension(pGF) * GFP_FEBITSIZE(cpGFpBasic(pGF));
         int maxOrderBits = 1+ cpGFpBasicDegreeExtension(pGF) * GFP_FEBITLEN(cpGFpBasic(pGF));
         BNU_CHUNK_T* pOrderData = BN_NUMBER(pOrder);
         int orderLen= BN_SIZE(pOrder);
         int orderBitSize = BITSIZE_BNU(pOrderData, orderLen);
         IPP_BADARG_RET(orderBitSize>maxOrderBits, ippStsRangeErr)
         ECP_ORDBITSIZE(pEC) = orderBitSize;
         ippsMontSet((Ipp32u*)pOrderData, BITS2WORD32_SIZE(orderBitSize), ECP_MONT_R(pEC));
      }

      {
         BNU_CHUNK_T* pCofactorData = BN_NUMBER(pCofactor);
         int cofactorLen= BN_SIZE(pCofactor);
         int cofactorBitSize = BITSIZE_BNU(pCofactorData, cofactorLen);
         IPP_BADARG_RET(cofactorBitSize>elemLen*BITSIZE(BNU_CHUNK_T), ippStsRangeErr)
         COPY_BNU(ECP_COFACTOR(pEC), pCofactorData, cofactorLen);
      }

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECGet,(IppsGFpState** const ppGF,
                                IppsGFpElement* pA, IppsGFpElement* pB,
                                const IppsGFpECState* pEC))
{
   IPP_BAD_PTR1_RET(pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );

   {
      const IppsGFpState* pGF = ECP_GFP(pEC);
      Ipp32u elementSize = GFP_FELEN(pGF);

      if(ppGF) {
         *ppGF = (IppsGFpState*)pGF;
      }

      if(pA) {
         IPP_BADARG_RET( !GFPE_TEST_ID(pA), ippStsContextMatchErr );
         IPP_BADARG_RET( GFPE_ROOM(pA)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
         cpGFpElementCopy(GFPE_DATA(pA), ECP_A(pEC), elementSize);
      }
      if(pB) {
         IPP_BADARG_RET( !GFPE_TEST_ID(pB), ippStsContextMatchErr );
         IPP_BADARG_RET( GFPE_ROOM(pB)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
         cpGFpElementCopy(GFPE_DATA(pB), ECP_B(pEC), elementSize);
      }

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECGetSubgroup,(IppsGFpState** const ppGF,
                                     IppsGFpElement* pX, IppsGFpElement* pY,
                                     IppsBigNumState* pOrder,
                                     IppsBigNumState* pCofactor,
                                     const IppsGFpECState* pEC))
{
   IPP_BAD_PTR1_RET(pEC);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );

   {
      const IppsGFpState* pGF = ECP_GFP(pEC);
      Ipp32u elementSize = GFP_FELEN(pGF);

      if(ppGF) {
         *ppGF = (IppsGFpState*)pGF;
      }

      if(pX) {
         IPP_BADARG_RET( !GFPE_TEST_ID(pX), ippStsContextMatchErr );
         IPP_BADARG_RET( GFPE_ROOM(pX)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
         cpGFpElementCopy(GFPE_DATA(pX), ECP_G(pEC), elementSize);
      }
      if(pY) {
         IPP_BADARG_RET( !GFPE_TEST_ID(pY), ippStsContextMatchErr );
         IPP_BADARG_RET( GFPE_ROOM(pY)!=GFP_FELEN(ECP_GFP(pEC)), ippStsOutOfRangeErr);
         cpGFpElementCopy(GFPE_DATA(pY), ECP_G(pEC)+elementSize, elementSize);
      }

      if(pOrder) {
         BNU_CHUNK_T* pOrderData = MNT_MODULUS(ECP_MONT_R(pEC));
         int orderBitSize = ECP_ORDBITSIZE(pEC);
         int orderLen = BITS_BNU_CHUNK(orderBitSize);
         FIX_BNU(pOrderData, orderLen);

         pOrder = (IppsBigNumState*)( IPP_ALIGNED_PTR(pOrder, BN_ALIGNMENT) );
         IPP_BADARG_RET(!BN_VALID_ID(pOrder), ippStsContextMatchErr);
         IPP_BADARG_RET(BN_ROOM(pOrder) < orderLen, ippStsLengthErr);

         ZEXPAND_COPY_BNU(BN_NUMBER(pOrder), BN_ROOM(pOrder), pOrderData, orderLen);
         BN_SIZE(pOrder) = orderLen;
         BN_SIGN(pOrder) = ippBigNumPOS;
      }

      if(pCofactor) {
         BNU_CHUNK_T* pCofactorData = ECP_COFACTOR(pEC);
         int cofactorLen = elementSize;
         FIX_BNU(pCofactorData, cofactorLen);

         pCofactor = (IppsBigNumState*)( IPP_ALIGNED_PTR(pCofactor, BN_ALIGNMENT) );
         IPP_BADARG_RET(!BN_VALID_ID(pCofactor), ippStsContextMatchErr);
         IPP_BADARG_RET(BN_ROOM(pCofactor) < cofactorLen, ippStsLengthErr);

         ZEXPAND_COPY_BNU(BN_NUMBER(pCofactor), BN_ROOM(pCofactor), pCofactorData, cofactorLen);
         BN_SIZE(pCofactor) = cofactorLen;
         BN_SIGN(pCofactor) = ippBigNumPOS;
      }

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECScratchBufferSize,(int nScalars, const IppsGFpECState* pEC, int* pBufferSize))
{
   IPP_BAD_PTR2_RET(pEC, pBufferSize);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );

   IPP_BADARG_RET( (0>=nScalars)||(nScalars>IPP_MAX_EXPONENT_NUM), ippStsBadArgErr);

   {
      /* select constant size of window */
      const int w = 5;
      /* number of table entries */
      const int nPrecomputed = 1<<(w-1);  /* because of signed digit representation of scalar is uses */

      int pointDataSize = ECP_POINTLEN(pEC)*sizeof(BNU_CHUNK_T);

      *pBufferSize = nScalars * pointDataSize*nPrecomputed + CACHE_LINE_SIZE;

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECVerify,(IppECResult* pResult, IppsGFpECState* pEC, Ipp8u* pScratchBuffer))
{
   IPP_BAD_PTR3_RET(pEC, pResult, pScratchBuffer);
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET( !ECP_TEST_ID(pEC), ippStsContextMatchErr );

   *pResult = ippECValid;

   {
      IppsGFpState* pGF = ECP_GFP(pEC);
      int elemLen = GFP_FELEN(pGF);

      /*
      // check discriminant ( 4*A^3 + 27*B^2 != 0 mod P)
      */
      if(ippECValid == *pResult) {
         BNU_CHUNK_T* pT = cpGFpGetPool(1, pGF);
         BNU_CHUNK_T* pU = cpGFpGetPool(1, pGF);

         if(ECP_SPECIFIC(pEC)==ECP_EPID2)
            cpGFpElementPadd(pT, elemLen, 0);            /* T = 4*A^3 = 0 */
         else {
            pGF->add(pT, ECP_A(pEC), ECP_A(pEC), pGF);   /* T = 4*A^3 */
            pGF->sqr(pT, pT, pGF);
            pGF->mul(pT, ECP_A(pEC), pT, pGF);
         }

         pGF->add(pU, ECP_B(pEC), ECP_B(pEC), pGF);      /* U = 9*B^2 */
         pGF->add(pU, pU, ECP_B(pEC), pGF);
         pGF->sqr(pU, pU, pGF);

         pGF->add(pT, pU, pT, pGF);                      /* T += 3*U */
         pGF->add(pT, pU, pT, pGF);
         pGF->add(pT, pU, pT, pGF);

         *pResult = GFP_IS_ZERO(pT, elemLen)? ippECIsZeroDiscriminant: ippECValid;

         cpGFpReleasePool(2, pGF);
      }

      /*
      // check base point and it order
      */
      if(ippECValid == *pResult) {
         IppsGFpECPoint G;
         cpEcGFpInitPoint(&G, ECP_G(pEC), ECP_AFFINE_POINT|ECP_FINITE_POINT, pEC);

         /* check G != infinity */
         *pResult = gfec_IsPointAtInfinity(&G)? ippECPointIsAtInfinite : ippECValid;

         /* check G lies on EC */
         if(ippECValid == *pResult)
            *pResult = gfec_IsPointOnCurve(&G, pEC)? ippECValid : ippECPointIsNotValid;

         /* check Gorder*G = infinity */
         if(ippECValid == *pResult) {
            IppsGFpECPoint T;
            cpEcGFpInitPoint(&T, cpEcGFpGetPool(1, pEC),0, pEC);

            //gfec_MulPoint(&T, &G, MNT_MODULUS(ECP_MONT_R(pEC)), BITS_BNU_CHUNK(ECP_ORDBITSIZE(pEC)), pEC, pScratchBuffer);
            gfec_MulBasePoint(&T, MNT_MODULUS(ECP_MONT_R(pEC)), BITS_BNU_CHUNK(ECP_ORDBITSIZE(pEC)), pEC, pScratchBuffer);

            *pResult = gfec_IsPointAtInfinity(&T)? ippECValid : ippECInvalidOrder;

            cpEcGFpReleasePool(1, pEC);
         }
      }

      /*
      // check order==P
      */
      if(ippECValid == *pResult) {
         IppsGFpState* pGF_local = ECP_GFP(pEC);
         BNU_CHUNK_T* pPrime = GFP_MODULUS(pGF_local);
         int primeLen = GFP_FELEN(pGF_local);

         IppsMontState* pR = ECP_MONT_R(pEC);
         BNU_CHUNK_T* pOrder = MNT_MODULUS(pR);
         int orderLen = MNT_SIZE(pR);

         *pResult = (primeLen==orderLen && GFP_EQ(pPrime, pOrder, primeLen))? ippECIsWeakSSSA : ippECValid;
      }

      return ippStsNoErr;
   }
}
