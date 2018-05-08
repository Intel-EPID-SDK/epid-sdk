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
//               Intel(R) Integrated Performance Primitives
//                   Cryptographic Primitives (ippcp)
// 
//  Contents:
// 
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpbn.h"
#include "pcpmontgomery.h"
#include "pcpmulbnukara.h"
#include "pcptool.h"

//gres: temporary excluded: #include <assert.h>

/* Auxilirary function */
__INLINE int cpGetBitSize(Ipp32u offset, Ipp32u val)
{
    int bitSize = 32;
    if (val == 0) return 0;
    while ((val & (1 << bitSize)) == 0) bitSize--;
    return offset + bitSize;
}

IppStatus cpMontGetSize(cpSize maxLen32, int poolLength, cpSize* pCtxSize)
{
   {
      int size = 0;
      int maxBitSize = maxLen32 << 5;
      gsModEngineGetSize(maxBitSize, poolLength, &size);

      *pCtxSize = sizeof(IppsMontState)
               + (cpSize)size
               + MONT_ALIGNMENT-1;

      return ippStsNoErr;
   }
}


IppStatus cpMontInit(int maxLen32, int poolLength, IppsMontState* pMont)
{
   pMont = (IppsMontState*)( IPP_ALIGNED_PTR(pMont, MONT_ALIGNMENT) );
   {
      int maxBitSize = ((maxLen32) << 5);

      MNT_ROOM( pMont )     = INTERNAL_BNU_LENGTH(maxLen32);
      MNT_ENGINE  ( pMont ) = (gsModEngine*)((Ipp8u*)pMont + sizeof(IppsMontState));

      MNT_ID(pMont) = idCtxMontgomery;

      gsModEngineInit(MNT_ENGINE(pMont), NULL, maxBitSize, poolLength, gsModArithMont());

      return ippStsNoErr;
   }
}

IppStatus cpMontSet(const Ipp32u* pModulus, cpSize len32, IppsMontState* pMont)
{
   IPP_BADARG_RET(len32<1, ippStsLengthErr);

   /* modulus is not an odd number */
   IPP_BADARG_RET((pModulus[0] & 1) == 0, ippStsBadModulusErr);
   IPP_BADARG_RET(MNT_ROOM(pMont)<(int)(INTERNAL_BNU_LENGTH(len32)), ippStsOutOfRangeErr);

   {
      const int poolLen  = MOD_MAXPOOL(MNT_ENGINE(pMont));
      int modulusBitSize = cpGetBitSize((len32 - 1) << 5, pModulus[len32-1]);

      gsModEngineInit(MNT_ENGINE(pMont), pModulus, modulusBitSize, poolLen, gsModArithMont());

      return ippStsNoErr;
   }
}

/*F*
// Name: ippsMontGetSize
//
// Purpose: Specifies size of buffer in bytes.
//
// Returns:                Reason:
//      ippStsNullPtrErr    pCtxSize==NULL
//      ippStsLengthErr     maxLen32 < 1
//                          maxLen32 > BITS2WORD32_SIZE(BN_MAXBITSIZE)
//      ippStsNoErr         no errors
//
// Parameters:
//      method    selected exponential method (unused parameter)
//      maxLen32  max modulus length (in Ipp32u chunks)
//      pCtxSize  size of context
//
// Notes: Function always use method=ippBinaryMethod,
//        so this parameter is ignored
*F*/
IPPFUN(IppStatus, ippsMontGetSize, (IppsExpMethod method, cpSize maxLen32, cpSize* pCtxSize))
{
   IPP_BAD_PTR1_RET(pCtxSize);
   IPP_BADARG_RET(maxLen32<1 || maxLen32>BITS2WORD32_SIZE(BN_MAXBITSIZE), ippStsLengthErr);

   UNREFERENCED_PARAMETER(method);

   {
      return cpMontGetSize(maxLen32, MONT_DEFAULT_POOL_LENGTH, pCtxSize);
   }
}

/*F*
// Name: ippsMontInit
//
// Purpose: Initializes the symbolic data structure and partitions the
//      specified buffer space.
//
// Returns:                Reason:
//      ippStsNullPtrErr    pMont==NULL
//      ippStsLengthErr     maxLen32 < 1
//                          maxLen32 > BITS2WORD32_SIZE(BN_MAXBITSIZE)
//      ippStsNoErr         no errors
//
// Parameters:
//      method    selected exponential method (unused parameter)
//      maxLen32  max modulus length (in Ipp32u chunks)
//      pMont     pointer to Montgomery context
*F*/
IPPFUN(IppStatus, ippsMontInit,(IppsExpMethod method, int maxLen32, IppsMontState* pMont))
{
   IPP_BADARG_RET(maxLen32<1 || maxLen32>BITS2WORD32_SIZE(BN_MAXBITSIZE), ippStsLengthErr);

   IPP_BAD_PTR1_RET(pMont);

   UNREFERENCED_PARAMETER(method);

   {
      return cpMontInit(maxLen32, MONT_DEFAULT_POOL_LENGTH, pMont);
   }
}

void cpPackMontCtx(const IppsMontState* pCtx, Ipp8u* pBuffer)
{
   IppsMontState* pAlignedBuffer = (IppsMontState*)(IPP_ALIGNED_PTR((pBuffer), MONT_ALIGNMENT));

   /* size of context (bytes) */
   int ctxSize = sizeof(IppsMontState);
   CopyBlock(pCtx, pAlignedBuffer, ctxSize);

   pBuffer = (Ipp8u*)pAlignedBuffer + sizeof(IppsMontState);

   gsPackModEngineCtx(MNT_ENGINE(pCtx), pBuffer);
}

void cpUnpackMontCtx(const Ipp8u* pBuffer, IppsMontState* pCtx)
{
   IppsMontState* pAlignedBuffer = (IppsMontState*)(IPP_ALIGNED_PTR((pBuffer), MONT_ALIGNMENT));

   /* size of context (bytes) */
   int ctxSize = sizeof(IppsMontState);
   CopyBlock(pAlignedBuffer, pCtx, ctxSize);

   pBuffer = (Ipp8u*)pAlignedBuffer + sizeof(IppsMontState);

   gsUnpackModEngineCtx(pBuffer, MNT_ENGINE(pCtx));
}


/*F*
// Name: ippsMontSet
//
// Purpose: Setup modulus value
//
// Returns:                   Reason:
//    ippStsNullPtrErr           pMont==NULL
//                               pModulus==NULL
//    ippStsContextMatchErr      !MNT_VALID_ID()
//    ippStsLengthErr            len32<1
//    ippStsNoErr                no errors
//
// Parameters:
//    pModulus    pointer to the modulus buffer
//    len32       length of the  modulus (in Ipp32u chunks).
//    pMont       pointer to the context
*F*/
IPPFUN(IppStatus, ippsMontSet,(const Ipp32u* pModulus, cpSize len32, IppsMontState* pMont))
{
   IPP_BAD_PTR2_RET(pModulus, pMont);
   pMont = (IppsMontState*)(IPP_ALIGNED_PTR((pMont), MONT_ALIGNMENT));
   IPP_BADARG_RET(!MNT_VALID_ID(pMont), ippStsContextMatchErr);

   IPP_BADARG_RET(len32<1, ippStsLengthErr);

   /* modulus is not an odd number */
   IPP_BADARG_RET((pModulus[0] & 1) == 0, ippStsBadModulusErr);
   IPP_BADARG_RET(((Ipp32u)MNT_ROOM(pMont) < INTERNAL_BNU_LENGTH(len32)), ippStsOutOfRangeErr);

   {
      return cpMontSet(pModulus, len32, pMont);
   }
}

/*F*
// Name: ippsMontGet
//
// Purpose: Extracts modulus.
//
// Returns:                   Reason:
//    ippStsNullPtrErr           pMont==NULL
//                               pModulus==NULL
//                               pLen32==NULL
//    ippStsContextMatchErr      !MNT_VALID_ID()
//    ippStsNoErr                no errors
//
// Parameters:
//    pModulus    pointer to the modulus buffer
//    pLen32      pointer to the modulus length (in Ipp32u chunks).
//    pMont       pointer to the context
*F*/
IPPFUN(IppStatus, ippsMontGet,(Ipp32u* pModulus, cpSize* pLen32, const IppsMontState* pMont))
{
    IPP_BAD_PTR3_RET(pMont, pModulus, pLen32);

   pMont = (IppsMontState*)(IPP_ALIGNED_PTR((pMont), MONT_ALIGNMENT));
   IPP_BADARG_RET(!MNT_VALID_ID(pMont), ippStsContextMatchErr);

   {
      cpSize len32 = MOD_LEN(MNT_ENGINE(pMont))*sizeof(BNU_CHUNK_T)/sizeof(Ipp32u);
      Ipp32u* bnData = (Ipp32u*) MOD_MODULUS( MNT_ENGINE(pMont) );

      FIX_BNU(bnData, len32);
      COPY_BNU(pModulus, bnData, len32);
      *pLen32 = len32;

      return ippStsNoErr;
   }
}

/*F*
// Name: ippsMontForm
//
// Purpose: Converts input into Montgomery domain.
//
// Returns:                   Reason:
//    ippStsNullPtrErr           pMont==NULL
//                               pA==NULL
//                               pR==NULL
// ippStsContextMatchErr         !MNT_VALID_ID()
//                               !BN_VALID_ID(pA)
//                               !BN_VALID_ID(pR)
//      ippStsBadArgErr          A < 0.
//      ippStsScaleRangeErr      A >= Modulus.
//      ippStsOutOfRangeErr      R can't hold result
//      ippStsNoErr              no errors
//
// Parameters:
//    pA    pointer to the input [0, modulus-1]
//    pMont Montgomery context
//    pR    pointer to the output (A*R mod modulus)
*F*/
IPPFUN(IppStatus, ippsMontForm,(const IppsBigNumState* pA, IppsMontState* pMont, IppsBigNumState* pR))
{
   IPP_BAD_PTR3_RET(pMont, pA, pR);

   pMont = (IppsMontState*)(IPP_ALIGNED_PTR((pMont), MONT_ALIGNMENT));
   pA = (IppsBigNumState*)( IPP_ALIGNED_PTR(pA, BN_ALIGNMENT) );
   pR = (IppsBigNumState*)( IPP_ALIGNED_PTR(pR, BN_ALIGNMENT) );

   IPP_BADARG_RET(!MNT_VALID_ID(pMont), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pA), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pR), ippStsContextMatchErr);

   IPP_BADARG_RET(BN_SIGN(pA) != ippBigNumPOS, ippStsBadArgErr);
   IPP_BADARG_RET(cpCmp_BNU(BN_NUMBER(pA), BN_SIZE(pA), MOD_MODULUS( MNT_ENGINE(pMont) ), MOD_LEN( MNT_ENGINE(pMont) )) >= 0, ippStsScaleRangeErr);
   IPP_BADARG_RET(BN_ROOM(pR) < MOD_LEN( MNT_ENGINE(pMont) ), ippStsOutOfRangeErr);

   {
      const int usedPoolLen = 1;
      cpSize nsM = MOD_LEN( MNT_ENGINE(pMont) );
      BNU_CHUNK_T* pDataA  = gsModPoolAlloc(MNT_ENGINE(pMont), usedPoolLen);
      //gres: temporary excluded: assert(NULL!=pDataA);

      ZEXPAND_COPY_BNU(pDataA, nsM, BN_NUMBER(pA), BN_SIZE(pA));

      MOD_METHOD( MNT_ENGINE(pMont) )->encode(BN_NUMBER(pR), pDataA, MNT_ENGINE(pMont));

      FIX_BNU(BN_NUMBER(pR), nsM);
      BN_SIZE(pR) = nsM;
      BN_SIGN(pR) = ippBigNumPOS;

      gsModPoolFree(MNT_ENGINE(pMont), usedPoolLen);
   }

   return ippStsNoErr;
}


/*F*
// Name: ippsMontMul
//
// Purpose: Computes Montgomery modular multiplication for positive big
//      number integers of Montgomery form. The following pseudocode
//      represents this function:
//      r <- ( a * b * R^(-1) ) mod m
//
// Returns:                Reason:
//      ippStsNoErr         Returns no error.
//      ippStsNullPtrErr    Returns an error when pointers are null.
//      ippStsBadArgErr     Returns an error when a or b is a negative integer.
//      ippStsScaleRangeErr Returns an error when a or b is more than m.
//      ippStsOutOfRangeErr Returns an error when IppsBigNumState *r is larger than
//                          IppsMontState *m.
//      ippStsContextMatchErr Returns an error when the context parameter does
//                          not match the operation.
//
// Parameters:
//      a   Multiplicand within the range [0, m - 1].
//      b   Multiplier within the range [0, m - 1].
//      m   Modulus.
//      r   Montgomery multiplication result.
//
// Notes: The size of IppsBigNumState *r should not be less than the data
//      length of the modulus m.
*F*/
IPPFUN(IppStatus, ippsMontMul, (const IppsBigNumState* pA, const IppsBigNumState* pB, IppsMontState* pMont, IppsBigNumState* pR))
{
   IPP_BAD_PTR4_RET(pA, pB, pMont, pR);

   pMont = (IppsMontState*)(IPP_ALIGNED_PTR((pMont), MONT_ALIGNMENT));
   pA = (IppsBigNumState*)( IPP_ALIGNED_PTR(pA, BN_ALIGNMENT) );
   pB = (IppsBigNumState*)( IPP_ALIGNED_PTR(pB, BN_ALIGNMENT) );
   pR = (IppsBigNumState*)( IPP_ALIGNED_PTR(pR, BN_ALIGNMENT) );

   IPP_BADARG_RET(!MNT_VALID_ID(pMont), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pA), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pB), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pR), ippStsContextMatchErr);

   IPP_BADARG_RET(BN_NEGATIVE(pA) || BN_NEGATIVE(pB), ippStsBadArgErr);
   IPP_BADARG_RET(cpCmp_BNU(BN_NUMBER(pA), BN_SIZE(pA), MOD_MODULUS( MNT_ENGINE(pMont) ), MOD_LEN( MNT_ENGINE(pMont) )) >= 0, ippStsScaleRangeErr);
   IPP_BADARG_RET(cpCmp_BNU(BN_NUMBER(pB), BN_SIZE(pB), MOD_MODULUS( MNT_ENGINE(pMont) ), MOD_LEN( MNT_ENGINE(pMont) )) >= 0, ippStsScaleRangeErr);
   IPP_BADARG_RET(BN_ROOM(pR) < MOD_LEN( MNT_ENGINE(pMont) ), ippStsOutOfRangeErr);

   {
      const int usedPoolLen = 2;
      cpSize nsM = MOD_LEN( MNT_ENGINE(pMont) );
      BNU_CHUNK_T* pDataR  = BN_NUMBER(pR);
      BNU_CHUNK_T* pDataA  = gsModPoolAlloc(MNT_ENGINE(pMont), usedPoolLen);
      BNU_CHUNK_T* pDataB  = pDataA + nsM;
      //gres: temporary excluded: assert(NULL!=pDataA);

      ZEXPAND_COPY_BNU(pDataA, nsM, BN_NUMBER(pA), BN_SIZE(pA));
      ZEXPAND_COPY_BNU(pDataB, nsM, BN_NUMBER(pB), BN_SIZE(pB));

      MOD_METHOD( MNT_ENGINE(pMont) )->mul(pDataR, pDataA, pDataB, MNT_ENGINE(pMont));

      gsModPoolFree(MNT_ENGINE(pMont), usedPoolLen);

      FIX_BNU(pDataR, nsM);
      BN_SIZE(pR) = nsM;
      BN_SIGN(pR) = ippBigNumPOS;

      return ippStsNoErr;
   }
}


/*******************************************************************************
// Name:             ippsMontExp
// Description: ippsMontExp() computes the Montgomery exponentiation with exponent
//              IppsBigNumState *e to the given big number integer of Montgomery form
//              IppsBigNumState *a with respect to the modulus IppsMontState *m.
// Input Arguments: a - big number integer of Montgomery form within the
//                      range [0,m-1]
//                  e - big number exponent
//                  m - Montgomery modulus of IppsMontState.
// Output Arguments: r - the Montgomery exponentiation result.
// Returns: IPPC_STATUS_OK - No Error
//          IPPC_STATUS_MONT_BAD_MODULUS - If a>m or b>m or m>R or P_MONT *m has
//                                         not been initialized by the primitive
//                                         function ippsMontInit( ).
//          IPPC_STATUS_BAD_ARG - Bad Arguments
// Notes: IppsBigNumState *r should possess enough memory space as to hold the result
//        of the operation. i.e. both pointers r->d and r->buffer should possess
//        no less than (m->n->length) number of 32-bit words.
*******************************************************************************/
IPPFUN(IppStatus, ippsMontExp, (const IppsBigNumState* pA, const IppsBigNumState* pE, IppsMontState* pMont, IppsBigNumState* pR))
{
   IPP_BAD_PTR4_RET(pA, pE, pMont, pR);

   pMont = (IppsMontState*)(IPP_ALIGNED_PTR((pMont), MONT_ALIGNMENT));
   pA = (IppsBigNumState*)( IPP_ALIGNED_PTR(pA, BN_ALIGNMENT) );
   pE = (IppsBigNumState*)( IPP_ALIGNED_PTR(pE, BN_ALIGNMENT) );
   pR = (IppsBigNumState*)( IPP_ALIGNED_PTR(pR, BN_ALIGNMENT) );

   IPP_BADARG_RET(!MNT_VALID_ID(pMont), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pA), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pE), ippStsContextMatchErr);
   IPP_BADARG_RET(!BN_VALID_ID(pR), ippStsContextMatchErr);

   IPP_BADARG_RET(BN_ROOM(pR) <  MOD_LEN( MNT_ENGINE(pMont) ), ippStsOutOfRangeErr);
   /* check a */
   IPP_BADARG_RET(BN_NEGATIVE(pA), ippStsBadArgErr);
   IPP_BADARG_RET(cpCmp_BNU(BN_NUMBER(pA), BN_SIZE(pA), MOD_MODULUS( MNT_ENGINE(pMont) ), MOD_LEN( MNT_ENGINE(pMont) )) >= 0, ippStsScaleRangeErr);
   /* check e */
   IPP_BADARG_RET(BN_NEGATIVE(pE), ippStsBadArgErr);

   cpMontExpBin_BN(pR, pA, pE, MNT_ENGINE( pMont) );

   return ippStsNoErr;
}
