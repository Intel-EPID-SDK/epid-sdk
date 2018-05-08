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
//     Operations over GF(p) ectension.
// 
//     Context:
//        ippsGFpxGetSize
//        ippsGFpxInit
//        ippsGFpxInitBinomial
//        ippsGFpGetInfo
// 
*/

#include "owndefs.h"
#include "owncp.h"

#include "pcpgfpstuff.h"
#include "pcpgfpxstuff.h"
#include "pcptool.h"

/* Get context size */
static int cpGFExGetSize(int elemLen, int pelmLen, int numpe)
{
   int ctxSize = 0;

   /* size of GFp engine */
   ctxSize = sizeof(gsModEngine)
            + elemLen*sizeof(BNU_CHUNK_T)    /* modulus  */
            + pelmLen*sizeof(BNU_CHUNK_T)*numpe; /* pool */

   ctxSize = sizeof(IppsGFpState)   /* size of IppsGFPState*/
           + ctxSize;               /* GFpx engine */
   return ctxSize;
}

IPPFUN(IppStatus, ippsGFpxGetSize, (const IppsGFpState* pGroundGF, int deg, int* pSize))
{
   IPP_BAD_PTR2_RET(pGroundGF, pSize);
   IPP_BADARG_RET( deg<IPP_MIN_GF_EXTDEG || deg >IPP_MAX_GF_EXTDEG, ippStsBadArgErr);
   pGroundGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGroundGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGroundGF), ippStsContextMatchErr );

   #define MAX_GFx_SIZE     (1<<15)  /* max size (bytes) of GF element (32KB) */
   {
      int groundElmLen = GFP_FELEN(GFP_PMA(pGroundGF));
      Ipp64u elmLen64 = (Ipp64u)(groundElmLen) *sizeof(BNU_CHUNK_T) *deg;
      int elemLen = (int)LODWORD(elmLen64);
      *pSize = 0;
      IPP_BADARG_RET(elmLen64> MAX_GFx_SIZE, ippStsBadArgErr);

      *pSize = cpGFExGetSize(elemLen, elemLen, GFPX_POOL_SIZE)
             + GFP_ALIGNMENT;
      return ippStsNoErr;
   }
   #undef MAX_GFx_SIZE
}

/* the "static" specificator removed because of incorrect result under Linux-32, p8
   what's wrong? not know maybe compiler (icl 2017)
   need to check after switchng on icl 2018
   */
/*static*/ void InitGFpxCtx(const IppsGFpState* pGroundGF, int extDeg, const IppsGFpMethod* method, IppsGFpState* pGFpx)
{
   gsModEngine* pGFEp = GFP_PMA(pGroundGF);
   int elemLen = extDeg * GFP_FELEN(pGFEp);
   int elemLen32 = extDeg * GFP_FELEN32(pGFEp);

   Ipp8u* ptr = (Ipp8u*)pGFpx + sizeof(IppsGFpState);

   /* context identifier */
   GFP_ID(pGFpx) = idCtxGFP;
   GFP_PMA(pGFpx) = (gsModEngine*)ptr;
   {
      gsModEngine* pGFEx = GFP_PMA(pGFpx);

      /* clear whole context */
      PaddBlock(0, ptr, sizeof(gsModEngine));
      ptr += sizeof(gsModEngine);

      GFP_PARENT(pGFEx)    = pGFEp;
      GFP_EXTDEGREE(pGFEx) = extDeg;
      GFP_FEBITLEN(pGFEx)  = 0;//elemBitLen;
      GFP_FELEN(pGFEx)     = elemLen;
      GFP_FELEN32(pGFEx)   = elemLen32;
      GFP_PELEN(pGFEx)     = elemLen;
      GFP_METHOD(pGFEx)    = method->arith;
      GFP_MODULUS(pGFEx)   = (BNU_CHUNK_T*)(ptr);  ptr += elemLen * sizeof(BNU_CHUNK_T);  /* field polynomial */
      GFP_POOL(pGFEx)      = (BNU_CHUNK_T*)(ptr);                                         /* pool */
      GFP_MAXPOOL(pGFEx)   = GFPX_POOL_SIZE;
      GFP_USEDPOOL(pGFEx)  = 0;

      cpGFpElementPadd(GFP_MODULUS(pGFEx), elemLen, 0);
   }
}


/*F*
// Name: ippsGFpxInit
//
// Purpose: initializes finite field extension GF(p^d)
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pGFpx
//                               NULL == pGroundGF
//                               NULL == ppGroundElm
//                               NULL == method
//
//    ippStsContextMatchErr      incorrect pGroundGF's context ID
//                               incorrect ppGroundElm[i]'s context ID
//
//    ippStsOutOfRangeErr        size of ppGroundElm[i] does not equal to size of pGroundGF element
//
//    ippStsBadArgErr            IPP_MIN_GF_EXTDEG > extDeg || extDeg > IPP_MAX_GF_EXTDEG
//                                  (IPP_MIN_GF_EXTDEG==2, IPP_MAX_GF_EXTDEG==8)
//                               1>nElm || nElm>extDeg
//
//                               cpID_Poly!=method->modulusID  -- method does not refferenced to polynomial one
//                               method->modulusBitDeg!=extDeg -- fixed method does not match to degree extension
//
//    ippStsNoErr                no error
//
// Parameters:
//    pGroundGF      pointer to the context of the finite field is being extension
//    extDeg         decgree of extension
//    ppGroundElm[]  pointer to the array of extension field polynomial
//    nElm           number of coefficients above
//    method         pointer to the basic arithmetic metods
//    pGFpx          pointer to Finite Field context is being initialized
*F*/
IPPFUN(IppStatus, ippsGFpxInit,(const IppsGFpState* pGroundGF, int extDeg,
                                const IppsGFpElement* const ppGroundElm[], int nElm,
                                const IppsGFpMethod* method, IppsGFpState* pGFpx))
{
   IPP_BAD_PTR4_RET(pGFpx, pGroundGF, ppGroundElm, method);

   pGFpx = (IppsGFpState*)( IPP_ALIGNED_PTR(pGFpx, GFP_ALIGNMENT) );
   pGroundGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGroundGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGroundGF), ippStsContextMatchErr );

   /* test extension degree */
   IPP_BADARG_RET( extDeg<IPP_MIN_GF_EXTDEG || extDeg>IPP_MAX_GF_EXTDEG, ippStsBadArgErr);
   /* coeffs at (x^0), (x^1), ..., (x^(deg-1)) passed acually */
   /* considering normilized f(x), the coeff at (x^deg) is 1 and so could neither stored no passed */
   /* test if 1<=nElm<=extDeg */
   IPP_BADARG_RET( 1>nElm || nElm>extDeg, ippStsBadArgErr);

   /* test if method is polynomial based */
   IPP_BADARG_RET(cpID_Poly != (method->modulusID & cpID_Poly), ippStsBadArgErr);
   /* test if method is fixed polynomial based */
   IPP_BADARG_RET(method->modulusBitDeg && (method->modulusBitDeg!=extDeg), ippStsBadArgErr);

   InitGFpxCtx(pGroundGF, extDeg, method, pGFpx);

   {
      BNU_CHUNK_T* pPoly = GFP_MODULUS(GFP_PMA(pGFpx));
      int polyTermlen = GFP_FELEN(GFP_PMA(pGroundGF));
      int n;
      for(n=0; n<nElm; n++, pPoly+=polyTermlen) {
         const IppsGFpElement* pGroundElm = ppGroundElm[n];

         /* test element */
         IPP_BAD_PTR1_RET(pGroundElm);
         IPP_BADARG_RET(!GFPE_TEST_ID(pGroundElm), ippStsContextMatchErr);
         IPP_BADARG_RET(GFPE_ROOM(pGroundElm)!=polyTermlen, ippStsOutOfRangeErr);

         /* copy element */
         cpGFpElementCopy(pPoly, GFPE_DATA(pGroundElm), polyTermlen);
      }
   }

   return ippStsNoErr;
}

/*F*
// Name: ippsGFpxInitBinomial
//
// Purpose: initializes finite field extension GF(p^d)
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pGFpx
//                               NULL == pGroundGF
//                               NULL == ppGroundElm
//                               NULL == method
//
//    ippStsContextMatchErr      incorrect pGroundGF's context ID
//                               incorrect pGroundElm's context ID
//
//    ippStsOutOfRangeErr        size of ppGroundElm does not equal to size of pGroundGF element
//
//    ippStsBadArgErr            IPP_MIN_GF_EXTDEG > extDeg || extDeg > IPP_MAX_GF_EXTDEG
//                                  (IPP_MIN_GF_EXTDEG==2, IPP_MAX_GF_EXTDEG==8)
//
//                               cpID_Poly!=method->modulusID  -- method does not refferenced to polynomial one
//                               method->modulusBitDeg!=extDeg -- fixed method does not match to degree extension
//
//    ippStsNoErr                no error
//
// Parameters:
//    pGroundGF      pointer to the context of the finite field is being extension
//    extDeg         decgree of extension
//    ppGroundElm[]  pointer to the array of extension field polynomial
//    nElm           number of coefficients above
//    method         pointer to the basic arithmetic metods
//    pGFpx          pointer to Finite Field context is being initialized
*F*/
IPPFUN(IppStatus, ippsGFpxInitBinomial,(const IppsGFpState* pGroundGF, int extDeg,
                                        const IppsGFpElement* pGroundElm,
                                        const IppsGFpMethod* method,
                                        IppsGFpState* pGFpx))
{
   IPP_BAD_PTR4_RET(pGFpx, pGroundGF, pGroundElm, method);

   pGFpx = (IppsGFpState*)( IPP_ALIGNED_PTR(pGFpx, GFP_ALIGNMENT) );
   pGroundGF = (IppsGFpState*)( IPP_ALIGNED_PTR(pGroundGF, GFP_ALIGNMENT) );
   IPP_BADARG_RET( !GFP_TEST_ID(pGroundGF), ippStsContextMatchErr );

   IPP_BADARG_RET( !GFPE_TEST_ID(pGroundElm), ippStsContextMatchErr );
   IPP_BADARG_RET(GFPE_ROOM(pGroundElm)!=GFP_FELEN(GFP_PMA(pGroundGF)), ippStsOutOfRangeErr);

   IPP_BADARG_RET( extDeg<IPP_MIN_GF_EXTDEG || extDeg>IPP_MAX_GF_EXTDEG, ippStsBadArgErr);

   /* test method is binomial based */
   IPP_BADARG_RET(cpID_Binom != (method->modulusID & cpID_Binom), ippStsBadArgErr);

   /* test if method assums fixed degree extension */
   IPP_BADARG_RET(method->modulusBitDeg && (extDeg!=method->modulusBitDeg), ippStsBadArgErr);

   /* init context */
   InitGFpxCtx(pGroundGF, extDeg, method, pGFpx);

   /* store low-order coefficient of irresucible into the context */
   cpGFpElementCopy(GFP_MODULUS(GFP_PMA(pGFpx)), GFPE_DATA(pGroundElm), GFP_FELEN(GFP_PMA(pGroundGF)));

   return ippStsNoErr;
}
