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
//     Operations over GF(p).
// 
//     Context:
//        ippsGFpGetSize()
//        ippsGFpInit()
// 
//        ippsGFpElementGetSize()
//        ippsGFpElementInit()
// 
//        ippsGFpSetElement()
//        ippsGFpSetElementOctString()
//        ippsGFpSetElementRandom()
//        ippsGFpSetElementHash()
//        ippsGFpCpyElement()
//        ippsGFpGetElement()
//        ippsGFpGetElementOctString()
// 
//        ippsGFpCmpElement()
//        ippsGFpIsZeroElement()
//        ippsGFpIsUnityElement()
// 
//        ippsGFpSetPolyTerm()
//        ippsGFpGetPolyTerm()
// 
//        ippsGFpConj()
//        ippsGFpNeg()
//        ippsGFpInv()
//        ippsGFpSqrt()
//        ippsGFpAdd()
//        ippsGFpSub()
//        ippsGFpMul()
//        ippsGFpSqr()
//        ippsGFpExp()
//        ippsGFpMultiExp()
// 
//        ippsGFpAdd_GFpE()
//        ippsGFpSub_GFpE()
//        ippsGFpMul_GFpE()
// 
// 
*/
#include "owndefs.h"
#include "owncp.h"

#include "pcpgfpstuff.h"
#include "pcpgfpxstuff.h"
#include "pcphash.h"


int cpGFpGetSize(int bitSize)
{
   int ctxSize = 0;
   int elemLen = BITS_BNU_CHUNK(bitSize);
   int poolelemLen = elemLen + 1;

   int montgomeryCtxSize;
   int elemLen32 = BITS2WORD32_SIZE(bitSize);

   ippsMontGetSize(ippBinaryMethod, elemLen32, &montgomeryCtxSize);
   montgomeryCtxSize -= MONT_ALIGNMENT-1;

   ctxSize = sizeof(IppsGFpState)                           /* sizeof(IppsGFPState)*/
            +elemLen*sizeof(BNU_CHUNK_T)                    /* modulus */
            +elemLen*sizeof(BNU_CHUNK_T)                    /* half of modulus */
            +elemLen*sizeof(BNU_CHUNK_T)                    /* quadratic non-residue */
            +montgomeryCtxSize                              /* montgomery engine */
            +CACHE_LINE_SIZE                              /* pool padding */
            +poolelemLen*sizeof(BNU_CHUNK_T)*GF_POOL_SIZE;  /* pool */
   return ctxSize;
}

#if 0
IPPFUN(IppStatus, ippsGFpGetSize,(int bitSize, int* pSizeInBytes))
{
   IPP_BAD_PTR1_RET(pSizeInBytes);
   IPP_BADARG_RET((bitSize < 2) || (bitSize > GF_MAX_BITSIZE), ippStsSizeErr);

   {
      int elemLen32 = BITS2WORD32_SIZE(bitSize);
      int elemLen = BITS_BNU_CHUNK(bitSize);
      int poolelemLen = elemLen + 1;

      int montgomeryCtxSize;
      ippsMontGetSize(ippBinaryMethod, elemLen32, &montgomeryCtxSize);

      *pSizeInBytes = sizeof(IppsGFpState)                           /* sizeof(IppsGFPState)*/
                     +elemLen*sizeof(BNU_CHUNK_T)                    /* modulus */
                     +elemLen*sizeof(BNU_CHUNK_T)                    /* half of modulus */
                     +elemLen*sizeof(BNU_CHUNK_T)                    /* quadratic non-residue */
                     +montgomeryCtxSize                              /* montgomery engine */
                     +CACHE_LINE_SIZE-1                              /* pool padding */
                     +poolelemLen*sizeof(BNU_CHUNK_T)*GF_POOL_SIZE   /* pool */
                     +GFP_ALIGNMENT-1;                               /* context padding */
      return ippStsNoErr;
   }
}
#endif
IPPFUN(IppStatus, ippsGFpGetSize,(int bitSize, int* pSizeInBytes))
{
   IPP_BAD_PTR1_RET(pSizeInBytes);
   IPP_BADARG_RET((bitSize < 2) || (bitSize > GF_MAX_BITSIZE), ippStsSizeErr);

   *pSizeInBytes = cpGFpGetSize(bitSize)
                  +GFP_ALIGNMENT;
   return ippStsNoErr;
}


#if 0
static void gfpInitSqrt(IppsGFpState* pGF)
{
   int elemLen = GFP_FELEN(pGF);
   BNU_CHUNK_T* e = cpGFpGetPool(1, pGF);
   BNU_CHUNK_T* t = cpGFpGetPool(1, pGF);
   BNU_CHUNK_T* pMont1 = cpGFpGetPool(1, pGF);

   cpGFpElementCopyPadd(pMont1, elemLen, MNT_1(GFP_MONT(pGF)), elemLen);

   /* (modulus-1)/2 */
   cpLSR_BNU(e, GFP_MODULUS(pGF), elemLen, 1);

   /* find a non-square g, where g^{(modulus-1)/2} = -1 */
   cpGFpElementCopy(GFP_QNR(pGF), pMont1, elemLen);
   do {
      cpGFpAdd(GFP_QNR(pGF), pMont1, GFP_QNR(pGF), pGF);
      cpGFpExp(t, GFP_QNR(pGF), e, elemLen, pGF);
      cpGFpNeg(t, t, pGF);
   } while( !GFP_EQ(pMont1, t, elemLen) );

   cpGFpReleasePool(3, pGF);
}

IPPFUN(IppStatus, ippsGFpInit,(const IppsBigNumState* pPrime, int primeBitSize, const IppsGFpMethod* method, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pPrime, method, pGF);
   IPP_BADARG_RET((primeBitSize< IPP_MIN_GF_BITSIZE) || (primeBitSize> IPP_MAX_GF_BITSIZE), ippStsSizeErr);

   pPrime = (IppsBigNumState*)( IPP_ALIGNED_PTR(pPrime, BN_ALIGNMENT) );
   IPP_BADARG_RET(!BN_VALID_ID(pPrime), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_SIGN(pPrime)!= IppsBigNumPOS, ippStsBadArgErr);
   IPP_BADARG_RET(BITSIZE_BNU(BN_NUMBER(pPrime),BN_SIZE(pPrime)) != primeBitSize, ippStsBadArgErr);
   IPP_BADARG_RET((BN_SIZE(pPrime)==1) && (BN_NUMBER(pPrime)[0]<IPP_MIN_GF_CHAR), ippStsBadArgErr);

   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );

   {
      Ipp8u* ptr = (Ipp8u*)pGF;

      int elemLen32 = BITS2WORD32_SIZE(primeBitSize);
      int elemLen = BITS_BNU_CHUNK(primeBitSize);
      int poolelemLen = elemLen + 1;
      int montgomeryCtxSize;
      ippsMontGetSize(ippBinaryMethod, elemLen32, &montgomeryCtxSize);

      GFP_ID(pGF)      = idCtxGFP;
      GFP_DEGREE(pGF)  = 1;
      GFP_FEBITLEN(pGF)= primeBitSize;
      GFP_FELEN(pGF)   = elemLen;
      GFP_FELEN32(pGF) = elemLen32;
      GFP_PELEN(pGF)   = poolelemLen;
      FIELD_POLY_TYPE(pGF) = ARBITRARY;
      GFP_GROUNDGF(pGF)= pGF;

      /* set up methods */
      pGF->add = method->add;
      pGF->sub = method->sub;
      pGF->neg = method->neg;
      pGF->div2= method->div2;
      pGF->mul2= method->mul2;
      pGF->mul3= method->mul3;
      pGF->mul = method->mul;
      pGF->sqr = method->sqr;
      pGF->encode = method->encode;
      pGF->decode = method->decode;

      ptr += sizeof(IppsGFpState);
      GFP_MODULUS(pGF)  = (BNU_CHUNK_T*)(ptr);    ptr += elemLen*sizeof(BNU_CHUNK_T);
      GFP_HMODULUS(pGF) = (BNU_CHUNK_T*)(ptr);    ptr += elemLen*sizeof(BNU_CHUNK_T);
      GFP_QNR(pGF)      = (BNU_CHUNK_T*)(ptr);    ptr += elemLen*sizeof(BNU_CHUNK_T);
      GFP_MONT(pGF)     = (IppsMontState*)( IPP_ALIGNED_PTR((ptr), (MONT_ALIGNMENT)) ); ptr += montgomeryCtxSize;
      GFP_POOL(pGF)     = (BNU_CHUNK_T*)(IPP_ALIGNED_PTR(ptr, (int)sizeof(BNU_CHUNK_T)));

      ippsMontInit(ippBinaryMethod, elemLen32, GFP_MONT(pGF));
      ippsMontSet((Ipp32u*)BN_NUMBER(pPrime), elemLen32, GFP_MONT(pGF));

      /* modulus */
      cpGFpElementPadd(GFP_MODULUS(pGF), elemLen, 0);
      COPY_BNU((Ipp32u*)GFP_MODULUS(pGF), (Ipp32u*)BN_NUMBER(pPrime), elemLen32);
      /* half of modulus */
      cpGFpElementPadd(GFP_HMODULUS(pGF), elemLen, 0);
      cpLSR_BNU(GFP_HMODULUS(pGF), GFP_MODULUS(pGF), elemLen, 1);

      /* do some additional initialization to make sqrt operation faster */
      cpGFpElementPadd(GFP_QNR(pGF), elemLen, 0);
      gfpInitSqrt(pGF);

      return ippStsNoErr;
   }
}
#endif
//#if 0
IppStatus cpGFpInitGFp(int primeBitSize, IppsGFpState* pGF)
{
   IPP_BADARG_RET((primeBitSize< IPP_MIN_GF_BITSIZE) || (primeBitSize> IPP_MAX_GF_BITSIZE), ippStsSizeErr);
   IPP_BAD_PTR1_RET(pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );

   {
      Ipp8u* ptr = (Ipp8u*)pGF;

      int elemLen32 = BITS2WORD32_SIZE(primeBitSize);
      int elemLen = BITS_BNU_CHUNK(primeBitSize);
      int poolelemLen = elemLen + 1;
      int montgomeryCtxSize;
      ippsMontGetSize(ippBinaryMethod, elemLen32, &montgomeryCtxSize);

      GFP_ID(pGF)      = idCtxGFP;
      GFP_FEBITLEN(pGF)= primeBitSize;
      GFP_FELEN(pGF)   = elemLen;
      GFP_FELEN32(pGF) = elemLen32;
      GFP_PELEN(pGF)   = poolelemLen;
      GFP_DEGREE(pGF)  = 1;
      FIELD_POLY_TYPE(pGF) = ARBITRARY;
      GFP_GROUNDGF(pGF)= pGF;

      ptr += sizeof(IppsGFpState);
      GFP_MODULUS(pGF)  = (BNU_CHUNK_T*)(ptr);    ptr += elemLen*sizeof(BNU_CHUNK_T);
      GFP_HMODULUS(pGF) = (BNU_CHUNK_T*)(ptr);    ptr += elemLen*sizeof(BNU_CHUNK_T);
      GFP_QNR(pGF)      = (BNU_CHUNK_T*)(ptr);    ptr += elemLen*sizeof(BNU_CHUNK_T);
      GFP_MONT(pGF)     = (IppsMontState*)( IPP_ALIGNED_PTR((ptr), (MONT_ALIGNMENT)) ); ptr += montgomeryCtxSize;
      GFP_POOL(pGF)     = (BNU_CHUNK_T*)(IPP_ALIGNED_PTR(ptr, (int)sizeof(BNU_CHUNK_T)));

      cpGFpElementPadd(GFP_MODULUS(pGF), elemLen, 0);
      cpGFpElementPadd(GFP_HMODULUS(pGF), elemLen, 0);
      cpGFpElementPadd(GFP_QNR(pGF), elemLen, 0);

      ippsMontInit(ippBinaryMethod, elemLen32, GFP_MONT(pGF));

      return ippStsNoErr;
   }
}

IppStatus cpGFpSetGFp(const IppsBigNumState* pPrime, const IppsGFpMethod* method, IppsGFpState* pGF)
{
   IPP_BAD_PTR3_RET(pPrime, method, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );

   pPrime = (IppsBigNumState*)( IPP_ALIGNED_PTR(pPrime, BN_ALIGNMENT) );
   IPP_BADARG_RET(!BN_VALID_ID(pPrime), ippStsContextMatchErr);
   IPP_BADARG_RET(BN_SIGN(pPrime)!= IppsBigNumPOS, ippStsBadArgErr);
   IPP_BADARG_RET(BITSIZE_BNU(BN_NUMBER(pPrime),BN_SIZE(pPrime)) != GFP_FEBITLEN(pGF), ippStsBadArgErr);
   IPP_BADARG_RET((BN_SIZE(pPrime)==1) && (BN_NUMBER(pPrime)[0]<IPP_MIN_GF_CHAR), ippStsBadArgErr);

   {
      int elemLen = GFP_FELEN(pGF);
      int elemLen32 = GFP_FELEN32(pGF);

      /* set up methods */
      pGF->add = method->add;
      pGF->sub = method->sub;
      pGF->neg = method->neg;
      pGF->div2= method->div2;
      pGF->mul2= method->mul2;
      pGF->mul3= method->mul3;
      pGF->mul = method->mul;
      pGF->sqr = method->sqr;
      pGF->encode = method->encode;
      pGF->decode = method->decode;

      /* modulus */
      COPY_BNU((Ipp32u*)GFP_MODULUS(pGF), (Ipp32u*)BN_NUMBER(pPrime), elemLen32);
      /* half of modulus */
      cpLSR_BNU(GFP_HMODULUS(pGF), GFP_MODULUS(pGF), elemLen, 1);

      /* set up mont engine */
      ippsMontSet((Ipp32u*)BN_NUMBER(pPrime), elemLen32, GFP_MONT(pGF));

      return ippStsNoErr;
   }
}

static void gfpInitSqrt(IppsGFpState* pGF)
{
   int elemLen = GFP_FELEN(pGF);
   BNU_CHUNK_T* e = cpGFpGetPool(1, pGF);
   BNU_CHUNK_T* t = cpGFpGetPool(1, pGF);
   BNU_CHUNK_T* pMont1 = cpGFpGetPool(1, pGF);

   cpGFpElementCopyPadd(pMont1, elemLen, MNT_1(GFP_MONT(pGF)), elemLen);

   /* (modulus-1)/2 */
   cpLSR_BNU(e, GFP_MODULUS(pGF), elemLen, 1);

   /* find a non-square g, where g^{(modulus-1)/2} = -1 */
   cpGFpElementCopy(GFP_QNR(pGF), pMont1, elemLen);
   do {
      cpGFpAdd(GFP_QNR(pGF), pMont1, GFP_QNR(pGF), pGF);
      cpGFpExp(t, GFP_QNR(pGF), e, elemLen, pGF);
      cpGFpNeg(t, t, pGF);
   } while( !GFP_EQ(pMont1, t, elemLen) );

   cpGFpReleasePool(3, pGF);
}

IPPFUN(IppStatus, ippsGFpInit,(const IppsBigNumState* pPrime, int primeBitSize, const IppsGFpMethod* method, IppsGFpState* pGF))
{
   IppStatus sts;
   do {
      sts = cpGFpInitGFp(primeBitSize, pGF);
      if(ippStsNoErr!=sts) break;
      sts = cpGFpSetGFp(pPrime, method, pGF);
      if(ippStsNoErr!=sts) break;
      /* do some additional initialization to make sqrt operation faster */
      gfpInitSqrt(pGF);
   } while(0);
   return sts;
}
//#endif


IPPFUN(IppStatus, ippsGFpScratchBufferSize,(int nExponents, int ExpBitSize, const IppsGFpState* pGF, int* pBufferSize))
{
   IPP_BAD_PTR2_RET(pGF, pBufferSize);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   IPP_BADARG_RET( 0>=nExponents ||nExponents>IPP_MAX_EXPONENT_NUM, ippStsBadArgErr);
   IPP_BADARG_RET( 0>=ExpBitSize, ippStsBadArgErr);

   {
      int elmDataSize = GFP_FELEN(pGF)*sizeof(BNU_CHUNK_T);

      /* get window_size */
      int w = (nExponents==1)? cpGFpGetOptimalWinSize(ExpBitSize) : /* use optimal window size, if single-scalar operation */
                               nExponents;                          /* or pseudo-oprimal if multi-scalar operation */

      /* number of table entries */
      int nPrecomputed = 1<<w;

      *pBufferSize = elmDataSize*nPrecomputed + (CACHE_LINE_SIZE-1);

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpElementGetSize,(const IppsGFpState* pGF, int* pElementSize))
{
   IPP_BAD_PTR2_RET(pElementSize, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   *pElementSize = sizeof(IppsGFpElement)
                  +GFP_FELEN(pGF)*sizeof(BNU_CHUNK_T);
   return ippStsNoErr;
}


IPPFUN(IppStatus, ippsGFpElementInit,(const Ipp32u* pA, int nsA, IppsGFpElement* pR, IppsGFpState* pGF))
{
   IPP_BAD_PTR2_RET(pR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );

   IPP_BADARG_RET(0>nsA, ippStsSizeErr);

   {
      int elemLen = GFP_FELEN(pGF);

      Ipp8u* ptr = (Ipp8u*)pR;
      ptr += sizeof(IppsGFpElement);
      cpGFpElementConstruct(pR, (BNU_CHUNK_T*)ptr, elemLen);
      return ippsGFpSetElement(pA, nsA, pR, pGF);
   }
}

IPPFUN(IppStatus, ippsGFpSetElement,(const Ipp32u* pDataA, int nsA, IppsGFpElement* pElm, IppsGFpState* pGF))
{
   IPP_BAD_PTR2_RET(pElm, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr );

   IPP_BADARG_RET( !pDataA && (0<nsA), ippStsNullPtrErr);
   IPP_BADARG_RET( pDataA && !(0<=nsA && nsA<=GFP_FELEN32(pGF)), ippStsSizeErr );
///IPP_BADARG_RET( pDataA && !(0<nsA && BITS2WORD32_SIZE(BITSIZE_BNU32(pDataA,nsA))<=GFP_FEBITLEN(pGF)), ippStsSizeErr );

   IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(pGF), ippStsOutOfRangeErr);

   {
      IppStatus sts = ippStsNoErr;

   ///int elemLen32 = GFP_FELEN32(pGF);
   ///if(pDataA) FIX_BNU(pDataA, nsA);
   ///if(pDataA && (nsA>elemLen32)) IPP_ERROR_RET(ippStsOutOfRangeErr);

      {
         BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGF);
         int elemLen = GFP_FELEN(pGF);
         ZEXPAND_BNU(pTmp, 0, elemLen);
         if(pDataA && nsA)
            cpGFpxCopyToChunk(pTmp, pDataA, nsA, pGF);

         if(!cpGFpxSet(GFPE_DATA(pElm), pTmp, elemLen, pGF))
            sts = ippStsOutOfRangeErr;

         cpGFpReleasePool(1, pGF);
      }

      return sts;
   }
}

IPPFUN(IppStatus, ippsGFpSetElementOctString,(const Ipp8u* pStr, int strSize, IppsGFpElement* pElm, IppsGFpState* pGF))
{
   IPP_BAD_PTR2_RET(pElm, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr );

   IPP_BADARG_RET( (!pStr && 0<strSize), ippStsNullPtrErr);
   IPP_BADARG_RET( (pStr && !(0<strSize && strSize<=(int)(GFP_FELEN32(pGF)*sizeof(Ipp32u)))), ippStsSizeErr );

   IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(pGF), ippStsOutOfRangeErr);

   {
      IppsGFpState* pBasicGF = cpGFpBasic(pGF);
      int basicDeg = cpGFpBasicDegreeExtension(pGF);
      int basicElemLen = GFP_FELEN(pBasicGF);
      int basicSize = BITS2WORD8_SIZE(BITSIZE_BNU(GFP_MODULUS(pBasicGF),GFP_FELEN(pBasicGF)));

      BNU_CHUNK_T* pDataElm = GFPE_DATA(pElm);

      int deg, error;
      /* set element to zero */
      cpGFpElementPadd(pDataElm, GFP_FELEN(pGF), 0);

      /* convert oct string to element (from low to high) */
      for(deg=0, error=0; deg<basicDeg && !error; deg++) {
         int size = IPP_MIN(strSize, basicSize);
         error = NULL == cpGFpSetOctString(pDataElm, pStr, size, pBasicGF);

         pDataElm += basicElemLen;
         strSize -= size;
         pStr += size;
      }

      return error? ippStsOutOfRangeErr : ippStsNoErr;
   }
}


IPPFUN(IppStatus, ippsGFpSetElementRandom,(IppsGFpElement* pElm, IppsGFpState* pGF,
                                           IppBitSupplier rndFunc, void* pRndParam))
{
   IPP_BAD_PTR2_RET(rndFunc, pRndParam);
   IPP_BAD_PTR2_RET(pElm, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr );

   IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(pGF), ippStsOutOfRangeErr);

   cpGFpxRand(GFPE_DATA(pElm), pGF, rndFunc, pRndParam);
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpCpyElement, (const IppsGFpElement* pElmA, IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);


   cpGFpElementCopy(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFP_FELEN(pGF));
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpGetElement, (const IppsGFpElement* pElm, Ipp32u* pDataA, int nsA, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElm, pDataA, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr );

   IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(pGF), ippStsOutOfRangeErr);
   IPP_BADARG_RET( !(0<nsA && nsA>=GFP_FELEN32(pGF)), ippStsSizeErr );

   {
      int elemLen = GFP_FELEN(pGF);
      BNU_CHUNK_T* pTmp = cpGFpGetPool(1, pGF);

      cpGFpxGet(pTmp, elemLen, GFPE_DATA(pElm), pGF);
      cpGFpxCopyFromChunk(pDataA, pTmp, pGF);

      cpGFpReleasePool(1, pGF);
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpGetElementOctString,(const IppsGFpElement* pElm, Ipp8u* pStr, int strSize, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pStr, pElm, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr );

   IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(pGF), ippStsOutOfRangeErr);
   IPP_BADARG_RET( 0>=strSize, ippStsSizeErr );

   {
      IppsGFpState* pBasicGF = cpGFpBasic(pGF);
      int basicDeg = cpGFpBasicDegreeExtension(pGF);
      int basicElemLen = GFP_FELEN(pBasicGF);
      int basicSize = BITS2WORD8_SIZE(BITSIZE_BNU(GFP_MODULUS(pBasicGF),GFP_FELEN(pBasicGF)));

      BNU_CHUNK_T* pDataElm = GFPE_DATA(pElm);

      int deg;
      for(deg=0; deg<basicDeg; deg++) {
         int size = IPP_MIN(strSize, basicSize);
         cpGFpGetOctString(pStr, size, pDataElm, pBasicGF);

         pDataElm += basicElemLen;
         pStr += size;
         strSize -= size;
      }

      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpCmpElement,(const IppsGFpElement* pElmA, const IppsGFpElement* pElmB,
                                     int* pResult,
                                     const IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pElmB, pResult, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmB), ippStsContextMatchErr );

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmB)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);

   {
      int flag = cpGFpElementCmp(GFPE_DATA(pElmA), GFPE_DATA(pElmB), GFP_FELEN(pGF));
      if( GFP_IS_BASIC(pGF) )
         *pResult = (0==flag)? IPP_IS_EQ : (0<flag)? IPP_IS_GT : IPP_IS_LT;
      else
         *pResult = (0==flag)? IPP_IS_EQ : IPP_IS_NE;
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpIsZeroElement,(const IppsGFpElement* pElmA,
                                     int* pResult,
                                     const IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pResult, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );

   IPP_BADARG_RET( GFPE_ROOM(pElmA)!=GFP_FELEN(pGF), ippStsOutOfRangeErr);

   {
      int flag = GFP_IS_ZERO(GFPE_DATA(pElmA), GFP_FELEN(pGF));
      *pResult = (1==flag)? IPP_IS_EQ : IPP_IS_NE;
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpIsUnityElement,(const IppsGFpElement* pElmA,
                                     int* pResult,
                                     const IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pResult, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );

   IPP_BADARG_RET( GFPE_ROOM(pElmA)!=GFP_FELEN(pGF), ippStsOutOfRangeErr);

   {
      IppsGFpState* pBasicGF = cpGFpBasic(pGF);
      int basicElmLen = GFP_FELEN(pBasicGF);
      BNU_CHUNK_T* pUnity = MNT_1(GFP_MONT(pBasicGF));

      int elmLen = GFP_FELEN(pGF);
      int flag;

      FIX_BNU(pUnity, basicElmLen);
      FIX_BNU(GFPE_DATA(pElmA), elmLen);

      flag = (basicElmLen==elmLen) && (0 == cpGFpElementCmp(GFPE_DATA(pElmA), pUnity, elmLen));
      *pResult = (1==flag)? IPP_IS_EQ : IPP_IS_NE;
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpConj,(const IppsGFpElement* pElmA,
                                     IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( 2!=GFP_DEGREE(pGF), ippStsBadArgErr )

   cpGFpxConj(GFPE_DATA(pElmR), GFPE_DATA(pElmA), pGF);
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpNeg,(const IppsGFpElement* pElmA,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);

   pGF->neg(GFPE_DATA(pElmR), GFPE_DATA(pElmA), pGF);
   return ippStsNoErr;
}


IPPFUN(IppStatus, ippsGFpInv,(const IppsGFpElement* pElmA,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( GFP_IS_ZERO(GFPE_DATA(pElmA),GFP_FELEN(pGF)), ippStsDivByZeroErr );

   return NULL != cpGFpxInv(GFPE_DATA(pElmR), GFPE_DATA(pElmA), pGF)? ippStsNoErr : ippStsBadArgErr;
}


IPPFUN(IppStatus, ippsGFpSqrt,(const IppsGFpElement* pElmA,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFP_IS_BASIC(pGF), ippStsBadArgErr )
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);

   return cpGFpSqrt(GFPE_DATA(pElmR), GFPE_DATA(pElmA), pGF)? ippStsNoErr : ippStsQuadraticNonResidueErr;
}


IPPFUN(IppStatus, ippsGFpAdd,(const IppsGFpElement* pElmA, const IppsGFpElement* pElmB,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pElmB, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmB), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmB)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);

   pGF->add(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFPE_DATA(pElmB), pGF);
   return ippStsNoErr;
}


IPPFUN(IppStatus, ippsGFpSub,(const IppsGFpElement* pElmA, const IppsGFpElement* pElmB,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pElmB, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmB), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmB)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);

   pGF->sub(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFPE_DATA(pElmB), pGF);
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpMul,(const IppsGFpElement* pElmA, const IppsGFpElement* pElmB,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pElmB, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmB), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmB)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);

   pGF->mul(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFPE_DATA(pElmB), pGF);
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpSqr,(const IppsGFpElement* pElmA,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR3_RET(pElmA, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);

   pGF->sqr(GFPE_DATA(pElmR), GFPE_DATA(pElmA), pGF);
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpAdd_PE,(const IppsGFpElement* pElmA, const IppsGFpElement* pParentElmB,
                                 IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pParentElmB, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pParentElmB), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   IPP_BADARG_RET( GFP_IS_BASIC(pGF), ippStsBadArgErr )

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( (GFPE_ROOM(pParentElmB)!=GFP_FELEN(GFP_GROUNDGF(pGF))), ippStsOutOfRangeErr);

   cpGFpxAdd_GFE(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFPE_DATA(pParentElmB), pGF);
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpSub_PE,(const IppsGFpElement* pElmA, const IppsGFpElement* pParentElmB,
                                 IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pParentElmB, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pParentElmB), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   IPP_BADARG_RET( GFP_IS_BASIC(pGF), ippStsBadArgErr )

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( (GFPE_ROOM(pParentElmB)!=GFP_FELEN(GFP_GROUNDGF(pGF))), ippStsOutOfRangeErr);

   cpGFpxSub_GFE(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFPE_DATA(pParentElmB), pGF);
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpMul_PE,(const IppsGFpElement* pElmA, const IppsGFpElement* pParentElmB,
                                 IppsGFpElement* pElmR, IppsGFpState* pGF))
{
   IPP_BAD_PTR4_RET(pElmA, pParentElmB, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pParentElmB), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   IPP_BADARG_RET( GFP_IS_BASIC(pGF), ippStsBadArgErr )

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);
   IPP_BADARG_RET( (GFPE_ROOM(pParentElmB)!=GFP_FELEN(GFP_GROUNDGF(pGF))), ippStsOutOfRangeErr);

   cpGFpxMul_GFE(GFPE_DATA(pElmR), GFPE_DATA(pElmA), GFPE_DATA(pParentElmB), pGF);
   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpExp,(const IppsGFpElement* pElmA, const IppsBigNumState* pE,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF,
                                    Ipp8u* pScratchBuffer))
{
   IPP_BAD_PTR4_RET(pElmA, pE, pElmR, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
   IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

   pE = (IppsBigNumState*)( IPP_ALIGNED_PTR(pE, BN_ALIGNMENT) );
   IPP_BADARG_RET( !BN_VALID_ID(pE), ippStsContextMatchErr );
   //IPP_BADARG_RET( BN_SIZE(pE) > GFP_FELEN(pGF), ippStsRangeErr );

   IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);

   cpGFpxExp(GFPE_DATA(pElmR), GFPE_DATA(pElmA), BN_NUMBER(pE), BN_SIZE(pE), pGF, pScratchBuffer);

   return ippStsNoErr;
}

IPPFUN(IppStatus, ippsGFpMultiExp,(const IppsGFpElement* const ppElmA[], const IppsBigNumState* const ppE[], int nItems,
                                    IppsGFpElement* pElmR, IppsGFpState* pGF,
                                    Ipp8u* pScratchBuffer))
{
   IPP_BAD_PTR2_RET(ppElmA, ppE);

   if(nItems==1)
      return ippsGFpExp(ppElmA[0], ppE[0], pElmR, pGF, pScratchBuffer);

   else {
      int n;

      /* test number of exponents */
      IPP_BADARG_RET(1>nItems || nItems>IPP_MAX_EXPONENT_NUM, ippStsBadArgErr);

      IPP_BAD_PTR2_RET(pElmR, pGF);

      pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
      IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr );
      IPP_BADARG_RET( !GFPE_TEST_ID(pElmR), ippStsContextMatchErr );

      IPP_BADARG_RET( GFPE_ROOM(pElmR)!=GFP_FELEN(pGF), ippStsOutOfRangeErr);

      /* test all ppElmA[] and ppE[] pairs */
      for(n=0; n<nItems; n++) {
         const IppsGFpElement* pElmA = ppElmA[n];
         const IppsBigNumState* pE = ppE[n];
         IPP_BAD_PTR2_RET(pElmA, pE);

         IPP_BADARG_RET( !GFPE_TEST_ID(pElmA), ippStsContextMatchErr );
         pE = (IppsBigNumState*)( IPP_ALIGNED_PTR(pE, BN_ALIGNMENT) );
         IPP_BADARG_RET( !BN_VALID_ID(pE), ippStsContextMatchErr );
         //IPP_BADARG_RET( BN_SIZE(pE) > GFP_FELEN(pGF), ippStsRangeErr );

         IPP_BADARG_RET( (GFPE_ROOM(pElmA)!=GFP_FELEN(pGF)) || (GFPE_ROOM(pElmR)!=GFP_FELEN(pGF)), ippStsOutOfRangeErr);
      }

      if(NULL==pScratchBuffer) {
         BNU_CHUNK_T* pTmpR = cpGFpGetPool(1, pGF);
         cpGFpxExp(GFPE_DATA(pElmR), GFPE_DATA(ppElmA[0]), BN_NUMBER(ppE[0]), BN_SIZE(ppE[0]), pGF, 0);
         for(n=1; n<nItems; n++) {
            cpGFpxExp(pTmpR, GFPE_DATA(ppElmA[n]), BN_NUMBER(ppE[n]), BN_SIZE(ppE[n]), pGF, 0);
            pGF->mul(GFPE_DATA(pElmR), GFPE_DATA(pElmR), pTmpR, pGF);
         }
         cpGFpReleasePool(1, pGF);
      }

      else {
         const BNU_CHUNK_T* ppAdata[IPP_MAX_EXPONENT_NUM];
         const BNU_CHUNK_T* ppEdata[IPP_MAX_EXPONENT_NUM];
         int nsEdataLen[IPP_MAX_EXPONENT_NUM];
         for(n=0; n<nItems; n++) {
            ppAdata[n] = GFPE_DATA(ppElmA[n]);
            ppEdata[n] = BN_NUMBER(ppE[n]);
            nsEdataLen[n] = BN_SIZE(ppE[n]);
         }
         cpGFpxMultiExp(GFPE_DATA(pElmR), ppAdata, ppEdata, nsEdataLen, nItems, pGF, pScratchBuffer);
      }
      return ippStsNoErr;
   }
}

IPPFUN(IppStatus, ippsGFpSetElementHash,(const Ipp8u* pMsg, int msgLen, IppsGFpElement* pElm, IppsGFpState* pGF, IppHashAlgId hashID))
{
   /* get algorithm id */
   hashID = cpValidHashAlg(hashID);
   IPP_BADARG_RET(ippHashAlg_Unknown==hashID, ippStsNotSupportedModeErr);

   /* test message length and pointer */
   IPP_BADARG_RET((msgLen<0), ippStsLengthErr);
   IPP_BADARG_RET((msgLen && !pMsg), ippStsNullPtrErr);

   IPP_BAD_PTR2_RET(pElm, pGF);
   pGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGF), ippStsContextMatchErr);
   IPP_BADARG_RET( !GFPE_TEST_ID(pElm), ippStsContextMatchErr);
   IPP_BADARG_RET( !GFP_IS_BASIC(pGF), ippStsBadArgErr);

   IPP_BADARG_RET( GFPE_ROOM(pElm)!=GFP_FELEN(pGF), ippStsOutOfRangeErr);

   {
      Ipp8u md[IPP_SHA512_DIGEST_BITSIZE/BYTESIZE];
      BNU_CHUNK_T hashVal[IPP_SHA512_DIGEST_BITSIZE/BITSIZE(BNU_CHUNK_T)+1]; /* +1 to meet cpMod_BNU() implementtaion specific */
      IppStatus sts = ippsHashMessage(pMsg, msgLen, md, hashID);

      if(ippStsNoErr==sts) {
         int elemLen = GFP_FELEN(pGF);
         int hashLen = cpHashAlgAttr[hashID].hashSize;
         int hashValLen = cpFromOctStr_BNU(hashVal, md, hashLen);
         hashValLen = cpMod_BNU(hashVal, hashValLen, GFP_MODULUS(pGF), elemLen);
         cpGFpSet(GFPE_DATA(pElm), hashVal, hashValLen, pGF);
      }
      return sts;
   }
}
