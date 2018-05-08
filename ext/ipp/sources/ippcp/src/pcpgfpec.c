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
//     EC over GF(p^m) definitinons
// 
//     Context:
//        ippsGFpECGetSize()
//        ippsGFpECInit()
//
//        ippsGFpECInitStd192r1
//        ippsGFpECInitStd224r1
//        ippsGFpECInitStd256r1
//        ippsGFpECInitStd384r1
//        ippsGFpECInitStd521r1
//        ippsGFpECInitStdSM2
//        ippsGFpECInitStdBN256
// 
//        ippsGFpECSet()
//        ippsGFpECSetSubgroup()
//
//        ippsGFpECBindGxyTblStd192r1
//        ippsGFpECBindGxyTblStd224r1
//        ippsGFpECBindGxyTblStd256r1
//        ippsGFpECBindGxyTblStd384r1
//        ippsGFpECBindGxyTblStd521r1
//        ippsGFpECBindGxyTblStdSM2
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
#include "pcpeccp.h"

//gres: temporary excluded: #include <assert.h>

int cpGFpECGetSize(int basicDeg, int basicElmBitSize)
{
   int ctxSize = 0;
   int elemLen = basicDeg*BITS_BNU_CHUNK(basicElmBitSize);

   int maxOrderBits = 1+ basicDeg*basicElmBitSize;
   #if defined(_LEGACY_ECCP_SUPPORT_)
   int maxOrderLen = BITS_BNU_CHUNK(maxOrderBits);
   #endif

   int modEngineCtxSize;
   if(ippStsNoErr==gsModEngineGetSize(maxOrderBits, MONT_DEFAULT_POOL_LENGTH, &modEngineCtxSize)) {

      ctxSize = sizeof(IppsGFpECState)
               +elemLen*sizeof(BNU_CHUNK_T)    /* EC coeff    A */
               +elemLen*sizeof(BNU_CHUNK_T)    /* EC coeff    B */
               +elemLen*sizeof(BNU_CHUNK_T)    /* generator G.x */
               +elemLen*sizeof(BNU_CHUNK_T)    /* generator G.y */
               +elemLen*sizeof(BNU_CHUNK_T)    /* generator G.z */
               +modEngineCtxSize               /* mont engine (R) */
               +elemLen*sizeof(BNU_CHUNK_T)    /* cofactor */
               #if defined(_LEGACY_ECCP_SUPPORT_)
               +2*elemLen*3*sizeof(BNU_CHUNK_T)    /* regular and ephemeral public  keys */
               +2*maxOrderLen*sizeof(BNU_CHUNK_T)  /* regular and ephemeral private keys */
               #endif
               +elemLen*sizeof(BNU_CHUNK_T)*3*EC_POOL_SIZE;
   }
   return ctxSize;
}

IPPFUN(IppStatus, ippsGFpECGetSize,(const IppsGFpState* pGF, int* pCtxSize))
{
   IPP_BAD_PTR2_RET(pGF, pCtxSize);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   {
      gsModEngine* pGFE = GFP_PMA(pGF);
      *pCtxSize = cpGFpECGetSize(cpGFpBasicDegreeExtension(pGFE), GFP_FEBITLEN(cpGFpBasic(pGFE)))
                + ECGFP_ALIGNMENT;
      return ippStsNoErr;
   }
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

      gsModEngine* pGFE = GFP_PMA(pGF);
      int elemLen = GFP_FELEN(pGFE);

      int maxOrderBits = 1+ cpGFpBasicDegreeExtension(pGFE) * GFP_FEBITLEN(cpGFpBasic(pGFE));
      #if defined(_LEGACY_ECCP_SUPPORT_)
      int maxOrdLen = BITS_BNU_CHUNK(maxOrderBits);
      #endif

      int modEngineCtxSize;
      gsModEngineGetSize(maxOrderBits, MONT_DEFAULT_POOL_LENGTH, &modEngineCtxSize);

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
      ECP_MONT_R(pEC) = (gsModEngine*)( IPP_ALIGNED_PTR((ptr), (MONT_ALIGNMENT)) ); ptr += modEngineCtxSize;
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
      gsModEngineInit(ECP_MONT_R(pEC), NULL, maxOrderBits, MONT_DEFAULT_POOL_LENGTH, gsModArithMont());

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

   {
      gsModEngine* pGFE = GFP_PMA(ECP_GFP(pEC));
      int elemLen = GFP_FELEN(pGFE);

      IPP_BADARG_RET( GFPE_ROOM(pA)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);
      IPP_BADARG_RET( GFPE_ROOM(pB)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);

      /* copy A */
      cpGFpElementPadd(ECP_A(pEC), elemLen, 0);
      cpGFpElementCopy(ECP_A(pEC), GFPE_DATA(pA), elemLen);
      /* and set up A-specific (a==0 or a==-3) if is */
      if(GFP_IS_ZERO(ECP_A(pEC), elemLen))
         ECP_SPECIFIC(pEC) = ECP_EPID2;

      cpGFpElementSetChunk(ECP_B(pEC), elemLen, 3);
      GFP_METHOD(pGFE)->encode(ECP_B(pEC), ECP_B(pEC), pGFE);
      GFP_METHOD(pGFE)->add(ECP_B(pEC), ECP_A(pEC), ECP_B(pEC), pGFE);
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

   IPP_BAD_PTR2_RET(pOrder, pCofactor);
   pOrder = (IppsBigNumState*)( IPP_ALIGNED_PTR(pOrder, BN_ALIGNMENT) );
   IPP_BADARG_RET(!BN_VALID_ID(pOrder), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_SIGN(pOrder)!= IppsBigNumPOS, ippStsBadArgErr);

   pCofactor = (IppsBigNumState*)( IPP_ALIGNED_PTR(pCofactor, BN_ALIGNMENT) );
   IPP_BADARG_RET(!BN_VALID_ID(pCofactor), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_SIGN(pCofactor)!= IppsBigNumPOS, ippStsBadArgErr);

   {
      gsModEngine* pGFE = GFP_PMA(ECP_GFP(pEC));
      int elemLen = GFP_FELEN(pGFE);

      IPP_BADARG_RET( GFPE_ROOM(pX)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);
      IPP_BADARG_RET( GFPE_ROOM(pY)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);

      gfec_SetPoint(ECP_G(pEC), GFPE_DATA(pX), GFPE_DATA(pY), pEC);

      {
         int maxOrderBits = 1+ cpGFpBasicDegreeExtension(pGFE) * GFP_FEBITLEN(cpGFpBasic(pGFE));
         BNU_CHUNK_T* pOrderData = BN_NUMBER(pOrder);
         int orderLen= BN_SIZE(pOrder);
         int orderBitSize = BITSIZE_BNU(pOrderData, orderLen);
         IPP_BADARG_RET(orderBitSize>maxOrderBits, ippStsRangeErr)
         ECP_ORDBITSIZE(pEC) = orderBitSize;
         gsModEngineInit(ECP_MONT_R(pEC),(Ipp32u*)pOrderData, orderBitSize, MONT_DEFAULT_POOL_LENGTH, gsModArithMont());
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


static void cpGFpECSetStd(int aLen, const BNU_CHUNK_T* pA,
                          int bLen, const BNU_CHUNK_T* pB,
                          int xLen, const BNU_CHUNK_T* pX,
                          int yLen, const BNU_CHUNK_T* pY,
                          int rLen, const BNU_CHUNK_T* pR,
                          BNU_CHUNK_T h,
                          IppsGFpECState* pEC)
{
   IppsGFpState* pGF = ECP_GFP(pEC);
   gsModEngine* pGFE = GFP_PMA(pGF);
   int elemLen = GFP_FELEN(pGFE);

   IppsGFpElement elmA, elmB;
   IppsBigNumState R, H;

   /* convert A ans B coeffs into GF elements */
   cpGFpElementConstruct(&elmA, cpGFpGetPool(1, pGFE), elemLen);
   cpGFpElementConstruct(&elmB, cpGFpGetPool(1, pGFE), elemLen);
   ippsGFpSetElement((Ipp32u*)pA, BITS2WORD32_SIZE(BITSIZE_BNU(pA,aLen)), &elmA, pGF);
   ippsGFpSetElement((Ipp32u*)pB, BITS2WORD32_SIZE(BITSIZE_BNU(pB,bLen)), &elmB, pGF);
   /* and set EC */
   ippsGFpECSet(&elmA, &elmB, pEC);

   /* construct R and H */
   cpConstructBN(&R, rLen, (BNU_CHUNK_T*)pR, NULL);
   cpConstructBN(&H, 1, &h, NULL);
   /* convert GX ans GY coeffs into GF elements */
   ippsGFpSetElement((Ipp32u*)pX, BITS2WORD32_SIZE(BITSIZE_BNU(pX,xLen)), &elmA, pGF);
   ippsGFpSetElement((Ipp32u*)pY, BITS2WORD32_SIZE(BITSIZE_BNU(pY,yLen)), &elmB, pGF);
   /* and init EC subgroup */
   ippsGFpECSetSubgroup(&elmA, &elmB, &R, &H, pEC);
}

IPPFUN(IppStatus, ippsGFpECInitStd128r1,(const IppsGFpState* pGF, IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pGF, pEC);

   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   {
      gsModEngine* pGFE = GFP_PMA(pGF);

      /* test if GF is prime GF */
      IPP_BADARG_RET(!GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      /* test underlying prime value*/
      IPP_BADARG_RET(cpCmp_BNU(secp128r1_p, BITS_BNU_CHUNK(128), GFP_MODULUS(pGFE), BITS_BNU_CHUNK(128)), ippStsBadArgErr);

      pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );

      ippsGFpECInit(pGF, NULL, NULL, pEC);
      cpGFpECSetStd(BITS_BNU_CHUNK(128), secp128r1_a,
                    BITS_BNU_CHUNK(128), secp128r1_b,
                    BITS_BNU_CHUNK(128), secp128r1_gx,
                    BITS_BNU_CHUNK(128), secp128r1_gy,
                    BITS_BNU_CHUNK(128), secp128r1_r,
                    secp128r1_h,
                    pEC);

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECInitStd128r2,(const IppsGFpState* pGF, IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pGF, pEC);

   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   {
      gsModEngine* pGFE = GFP_PMA(pGF);

      /* test if GF is prime GF */
      IPP_BADARG_RET(!GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      /* test underlying prime value*/
      IPP_BADARG_RET(cpCmp_BNU(secp128r2_p, BITS_BNU_CHUNK(128), GFP_MODULUS(pGFE), BITS_BNU_CHUNK(128)), ippStsBadArgErr);

      pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );

      ippsGFpECInit(pGF, NULL, NULL, pEC);
      cpGFpECSetStd(BITS_BNU_CHUNK(128), secp128r2_a,
                    BITS_BNU_CHUNK(128), secp128r2_b,
                    BITS_BNU_CHUNK(128), secp128r2_gx,
                    BITS_BNU_CHUNK(128), secp128r2_gy,
                    BITS_BNU_CHUNK(128), secp128r2_r,
                    secp128r2_h,
                    pEC);

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECInitStd192r1,(const IppsGFpState* pGF, IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pGF, pEC);

   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   {
      gsModEngine* pGFE = GFP_PMA(pGF);

      /* test if GF is prime GF */
      IPP_BADARG_RET(!GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      /* test underlying prime value*/
      IPP_BADARG_RET(cpCmp_BNU(secp192r1_p, BITS_BNU_CHUNK(192), GFP_MODULUS(pGFE), BITS_BNU_CHUNK(192)), ippStsBadArgErr);

      pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );

      ippsGFpECInit(pGF, NULL, NULL, pEC);
      cpGFpECSetStd(BITS_BNU_CHUNK(192), secp192r1_a,
                    BITS_BNU_CHUNK(192), secp192r1_b,
                    BITS_BNU_CHUNK(192), secp192r1_gx,
                    BITS_BNU_CHUNK(192), secp192r1_gy,
                    BITS_BNU_CHUNK(192), secp192r1_r,
                    secp192r1_h,
                    pEC);

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECInitStd224r1,(const IppsGFpState* pGF, IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pGF, pEC);

   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   {
      gsModEngine* pGFE = GFP_PMA(pGF);

      /* test if GF is prime GF */
      IPP_BADARG_RET(!GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      /* test underlying prime value*/
      IPP_BADARG_RET(cpCmp_BNU(secp224r1_p, BITS_BNU_CHUNK(224), GFP_MODULUS(pGFE), BITS_BNU_CHUNK(224)), ippStsBadArgErr);

      pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );

      ippsGFpECInit(pGF, NULL, NULL, pEC);
      cpGFpECSetStd(BITS_BNU_CHUNK(224), secp224r1_a,
                    BITS_BNU_CHUNK(224), secp224r1_b,
                    BITS_BNU_CHUNK(224), secp224r1_gx,
                    BITS_BNU_CHUNK(224), secp224r1_gy,
                    BITS_BNU_CHUNK(224), secp224r1_r,
                    secp224r1_h,
                    pEC);

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECInitStd256r1,(const IppsGFpState* pGF, IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pGF, pEC);

   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   {
      gsModEngine* pGFE = GFP_PMA(pGF);

   /* test if GF is prime GF */
      IPP_BADARG_RET(!GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      /* test underlying prime value*/
      IPP_BADARG_RET(cpCmp_BNU(secp256r1_p, BITS_BNU_CHUNK(256), GFP_MODULUS(pGFE), BITS_BNU_CHUNK(256)), ippStsBadArgErr);

      pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );

      ippsGFpECInit(pGF, NULL, NULL, pEC);
      cpGFpECSetStd(BITS_BNU_CHUNK(256), secp256r1_a,
                    BITS_BNU_CHUNK(256), secp256r1_b,
                    BITS_BNU_CHUNK(256), secp256r1_gx,
                    BITS_BNU_CHUNK(256), secp256r1_gy,
                    BITS_BNU_CHUNK(256), secp256r1_r,
                    secp256r1_h,
                    pEC);

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECInitStd384r1,(const IppsGFpState* pGF, IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pGF, pEC);

   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   {
      gsModEngine* pGFE = GFP_PMA(pGF);

      /* test if GF is prime GF */
      IPP_BADARG_RET(!GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      /* test underlying prime value*/
      IPP_BADARG_RET(cpCmp_BNU(secp384r1_p, BITS_BNU_CHUNK(384), GFP_MODULUS(pGFE), BITS_BNU_CHUNK(384)), ippStsBadArgErr);

      pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );

      ippsGFpECInit(pGF, NULL, NULL, pEC);
      cpGFpECSetStd(BITS_BNU_CHUNK(384), secp384r1_a,
                    BITS_BNU_CHUNK(384), secp384r1_b,
                    BITS_BNU_CHUNK(384), secp384r1_gx,
                    BITS_BNU_CHUNK(384), secp384r1_gy,
                    BITS_BNU_CHUNK(384), secp384r1_r,
                    secp384r1_h,
                    pEC);

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECInitStd521r1,(const IppsGFpState* pGF, IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pGF, pEC);

   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   {
      gsModEngine* pGFE = GFP_PMA(pGF);

      /* test if GF is prime GF */
      IPP_BADARG_RET(!GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      /* test underlying prime value*/
      IPP_BADARG_RET(cpCmp_BNU(secp521r1_p, BITS_BNU_CHUNK(521), GFP_MODULUS(pGFE), BITS_BNU_CHUNK(521)), ippStsBadArgErr);

      pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );

      ippsGFpECInit(pGF, NULL, NULL, pEC);
      cpGFpECSetStd(BITS_BNU_CHUNK(521), secp521r1_a,
                    BITS_BNU_CHUNK(521), secp521r1_b,
                    BITS_BNU_CHUNK(521), secp521r1_gx,
                    BITS_BNU_CHUNK(521), secp521r1_gy,
                    BITS_BNU_CHUNK(521), secp521r1_r,
                    secp521r1_h,
                    pEC);

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECInitStdSM2,(const IppsGFpState* pGF, IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pGF, pEC);

   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   {
      gsModEngine* pGFE = GFP_PMA(pGF);

      /* test if GF is prime GF */
      IPP_BADARG_RET(!GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      /* test underlying prime value*/
      IPP_BADARG_RET(cpCmp_BNU(tpmSM2_p256_p, BITS_BNU_CHUNK(256), GFP_MODULUS(pGFE), BITS_BNU_CHUNK(256)), ippStsBadArgErr);

      pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );

      ippsGFpECInit(pGF, NULL, NULL, pEC);
      cpGFpECSetStd(BITS_BNU_CHUNK(256), tpmSM2_p256_a,
                    BITS_BNU_CHUNK(256), tpmSM2_p256_b,
                    BITS_BNU_CHUNK(256), tpmSM2_p256_gx,
                    BITS_BNU_CHUNK(256), tpmSM2_p256_gy,
                    BITS_BNU_CHUNK(256), tpmSM2_p256_r,
                    tpmSM2_p256_h,
                    pEC);

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpECInitStdBN256,(const IppsGFpState* pGF, IppsGFpECState* pEC))
{
   IPP_BAD_PTR2_RET(pGF, pEC);

   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   {
      gsModEngine* pGFE = GFP_PMA(pGF);

      /* test if GF is prime GF */
      IPP_BADARG_RET(!GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      /* test underlying prime value*/
      IPP_BADARG_RET(cpCmp_BNU(tpmBN_p256p_p, BITS_BNU_CHUNK(256), GFP_MODULUS(pGFE), BITS_BNU_CHUNK(256)), ippStsBadArgErr);

      pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );

      ippsGFpECInit(pGF, NULL, NULL, pEC);
      cpGFpECSetStd(BITS_BNU_CHUNK(BNU_CHUNK_BITS), tpmBN_p256p_a,
                    BITS_BNU_CHUNK(BNU_CHUNK_BITS), tpmBN_p256p_b,
                    BITS_BNU_CHUNK(BNU_CHUNK_BITS), tpmBN_p256p_gx,
                    BITS_BNU_CHUNK(BNU_CHUNK_BITS), tpmBN_p256p_gy,
                    BITS_BNU_CHUNK(256),            tpmBN_p256p_r,
                    tpmBN_p256p_h,
                    pEC);

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
      gsModEngine* pGFE = GFP_PMA(pGF);
      Ipp32u elementSize = GFP_FELEN(pGFE);

      if(ppGF) {
         *ppGF = (IppsGFpState*)pGF;
      }

      if(pA) {
         IPP_BADARG_RET( !GFPE_TEST_ID(pA), ippStsContextMatchErr );
         IPP_BADARG_RET( GFPE_ROOM(pA)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);
         cpGFpElementCopy(GFPE_DATA(pA), ECP_A(pEC), elementSize);
      }
      if(pB) {
         IPP_BADARG_RET( !GFPE_TEST_ID(pB), ippStsContextMatchErr );
         IPP_BADARG_RET( GFPE_ROOM(pB)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);
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
      gsModEngine* pGFE = GFP_PMA(pGF);
      Ipp32u elementSize = GFP_FELEN(pGFE);

      if(ppGF) {
         *ppGF = (IppsGFpState*)pGF;
      }

      if(pX) {
         IPP_BADARG_RET( !GFPE_TEST_ID(pX), ippStsContextMatchErr );
         IPP_BADARG_RET( GFPE_ROOM(pX)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);
         cpGFpElementCopy(GFPE_DATA(pX), ECP_G(pEC), elementSize);
      }
      if(pY) {
         IPP_BADARG_RET( !GFPE_TEST_ID(pY), ippStsContextMatchErr );
         IPP_BADARG_RET( GFPE_ROOM(pY)!=GFP_FELEN(pGFE), ippStsOutOfRangeErr);
         cpGFpElementCopy(GFPE_DATA(pY), ECP_G(pEC)+elementSize, elementSize);
      }

      if(pOrder) {
         BNU_CHUNK_T* pOrderData = MOD_MODULUS(ECP_MONT_R(pEC));
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

static IppStatus cpGFpECBindGxyTbl(const BNU_CHUNK_T* pPrime,
                                   const cpPrecompAP* preComp,
                                   IppsGFpECState* pEC)
{
   IPP_BAD_PTR1_RET(pEC);
   /* use aligned EC context */
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   {
      IppsGFpState* pGF = ECP_GFP(pEC);
      gsModEngine* pGFE = GFP_PMA(pGF);
      Ipp32u elemLen = GFP_FELEN(pGFE);

      /* test if GF is prime GF */
      IPP_BADARG_RET(!GFP_IS_BASIC(pGFE), ippStsBadArgErr);
      /* test underlying prime value*/
      IPP_BADARG_RET(cpCmp_BNU(pPrime, elemLen, GFP_MODULUS(pGFE), elemLen), ippStsBadArgErr);

      {
         BNU_CHUNK_T* pbp_ec = ECP_G(pEC);
         int cmpFlag;
         BNU_CHUNK_T* pbp_tbl = cpEcGFpGetPool(1, pEC);

         selectAP select_affine_point = preComp->select_affine_point;
         const BNU_CHUNK_T* pTbl = preComp->pTbl;
         select_affine_point(pbp_tbl, pTbl, 1);

         /* check if EC's and G-table's Base Point is the same */
         cmpFlag = cpCmp_BNU(pbp_ec, elemLen*2, pbp_tbl, elemLen*2);

         cpEcGFpReleasePool(1, pEC);

         return cmpFlag? ippStsBadArgErr : ippStsNoErr;
      }
   }
}

IPPFUN(IppStatus, ippsGFpECBindGxyTblStd192r1,(IppsGFpECState* pEC))
{
   IppStatus sts = cpGFpECBindGxyTbl(secp192r1_p, gfpec_precom_nistP192r1_fun(), pEC);

   /* setup pre-computed g-table and point access function */
   if(ippStsNoErr==sts)
      ECP_PREMULBP(pEC) = gfpec_precom_nistP192r1_fun();

   return sts;
}

IPPFUN(IppStatus, ippsGFpECBindGxyTblStd224r1,(IppsGFpECState* pEC))
{
   IppStatus sts = cpGFpECBindGxyTbl(secp224r1_p, gfpec_precom_nistP224r1_fun(), pEC);

   /* setup pre-computed g-table and point access function */
   if(ippStsNoErr==sts)
      ECP_PREMULBP(pEC) = gfpec_precom_nistP224r1_fun();

   return sts;
}

IPPFUN(IppStatus, ippsGFpECBindGxyTblStd256r1,(IppsGFpECState* pEC))
{
   IppStatus sts = cpGFpECBindGxyTbl(secp256r1_p, gfpec_precom_nistP256r1_fun(), pEC);

   /* setup pre-computed g-table and point access function */
   if(ippStsNoErr==sts)
      ECP_PREMULBP(pEC) = gfpec_precom_nistP256r1_fun();

   return sts;
}

IPPFUN(IppStatus, ippsGFpECBindGxyTblStd384r1,(IppsGFpECState* pEC))
{
   IppStatus sts = cpGFpECBindGxyTbl(secp384r1_p, gfpec_precom_nistP384r1_fun(), pEC);

   /* setup pre-computed g-table and point access function */
   if(ippStsNoErr==sts)
      ECP_PREMULBP(pEC) = gfpec_precom_nistP384r1_fun();

   return sts;
}

IPPFUN(IppStatus, ippsGFpECBindGxyTblStd521r1,(IppsGFpECState* pEC))
{
   IppStatus sts = cpGFpECBindGxyTbl(secp521r1_p, gfpec_precom_nistP521r1_fun(), pEC);

   /* setup pre-computed g-table and point access function */
   if(ippStsNoErr==sts)
      ECP_PREMULBP(pEC) = gfpec_precom_nistP521r1_fun();

   return sts;
}

IPPFUN(IppStatus, ippsGFpECBindGxyTblStdSM2,(IppsGFpECState* pEC))
{
   IppStatus sts = cpGFpECBindGxyTbl(tpmSM2_p256_p, gfpec_precom_sm2_fun(), pEC);

   /* setup pre-computed g-table and point access function */
   if(ippStsNoErr==sts)
      ECP_PREMULBP(pEC) = gfpec_precom_sm2_fun();

   return sts;
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
      gsModEngine* pGFE = GFP_PMA(pGF);
      int elemLen = GFP_FELEN(pGFE);

      mod_mul mulF = GFP_METHOD(pGFE)->mul;
      mod_sqr sqrF = GFP_METHOD(pGFE)->sqr;
      mod_add addF = GFP_METHOD(pGFE)->add;

      /*
      // check discriminant ( 4*A^3 + 27*B^2 != 0 mod P)
      */
      if(ippECValid == *pResult) {
         BNU_CHUNK_T* pT = cpGFpGetPool(1, pGFE);
         BNU_CHUNK_T* pU = cpGFpGetPool(1, pGFE);
         //gres: temporary excluded: assert(NULL!=pT && NULL!=pU);

         if(ECP_SPECIFIC(pEC)==ECP_EPID2)
            cpGFpElementPadd(pT, elemLen, 0);         /* T = 4*A^3 = 0 */
         else {
            addF(pT, ECP_A(pEC), ECP_A(pEC), pGFE);   /* T = 4*A^3 */
            sqrF(pT, pT, pGFE);
            mulF(pT, ECP_A(pEC), pT, pGFE);
         }

         addF(pU, ECP_B(pEC), ECP_B(pEC), pGFE);      /* U = 9*B^2 */
         addF(pU, pU, ECP_B(pEC), pGFE);
         sqrF(pU, pU, pGFE);

         addF(pT, pU, pT, pGFE);                      /* T += 3*U */
         addF(pT, pU, pT, pGFE);
         addF(pT, pU, pT, pGFE);

         *pResult = GFP_IS_ZERO(pT, elemLen)? ippECIsZeroDiscriminant: ippECValid;

         cpGFpReleasePool(2, pGFE);
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
            gfec_MulBasePoint(&T, MOD_MODULUS(ECP_MONT_R(pEC)), BITS_BNU_CHUNK(ECP_ORDBITSIZE(pEC)), pEC, pScratchBuffer);

            *pResult = gfec_IsPointAtInfinity(&T)? ippECValid : ippECInvalidOrder;

            cpEcGFpReleasePool(1, pEC);
         }
      }

      /*
      // check order==P
      */
      if(ippECValid == *pResult) {
         BNU_CHUNK_T* pPrime = GFP_MODULUS(pGFE);
         int primeLen = GFP_FELEN(pGFE);

         gsModEngine* pR = ECP_MONT_R(pEC);
         BNU_CHUNK_T* pOrder = MOD_MODULUS(pR);
         int orderLen = MOD_LEN(pR);

         *pResult = (primeLen==orderLen && GFP_EQ(pPrime, pOrder, primeLen))? ippECIsWeakSSSA : ippECValid;
      }

      return ippStsNoErr;
   }
}
