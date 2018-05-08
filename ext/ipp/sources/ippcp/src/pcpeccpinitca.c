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
// 
//  Purpose:
//     Cryptography Primitive.
//     EC over Prime Finite Field (initialization)
// 
//  Contents:
//     ippsECCPGetSize()
//     ippsECCPGetSizeStd128r1()
//     ippsECCPGetSizeStd128r2()
//     ippsECCPGetSizeStd192r1()
//     ippsECCPGetSizeStd224r1()
//     ippsECCPGetSizeStd256r1()
//     ippsECCPGetSizeStd384r1()
//     ippsECCPGetSizeStd521r1()
//     ippsECCPGetSizeStdSM2()
// 
//     ippsECCPInit()
//     ippsECCPInitStd128r1()
//     ippsECCPInitStd128r2()
//     ippsECCPInitStd192r1()
//     ippsECCPInitStd224r1()
//     ippsECCPInitStd256r1()
//     ippsECCPInitStd384r1()
//     ippsECCPInitStd521r1()
//     ippsECCPInitStdSM2()
// 
// 
*/

#include "owndefs.h"
#include "owncp.h"
#include "pcpeccp.h"


/*F*
//    Name: ippsECCPGetSize
//
// Purpose: Returns size of ECC context (bytes).
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pSize
//
//    ippStsSizeErr              2>feBitSize
//
//    ippStsNoErr                no errors
//
// Parameters:
//    feBitSize   size of field element (bits)
//    pSize       pointer to the size of internal ECC context
//
*F*/
IPPFUN(IppStatus, ippsECCPGetSize, (int feBitSize, int *pSize))
{
   /* test size's pointer */
   IPP_BAD_PTR1_RET(pSize);

   /* test size of field element */
   IPP_BADARG_RET((2>feBitSize || feBitSize>EC_GFP_MAXBITSIZE), ippStsSizeErr);

   {
      /* size of GF context */
      //int gfCtxSize = cpGFpGetSize(feBitSize);
      int gfCtxSize = cpGFpGetSize(feBitSize, feBitSize+BITSIZE(BNU_CHUNK_T), GFP_POOL_SIZE);
      /* size of EC context */
      int ecCtxSize = cpGFpECGetSize(1, feBitSize);

      /* size of EC scratch buffer: 16 points of BITS_BNU_CHUNK(feBitSize)*3 length each */
      int ecScratchBufferSize = 16*(BITS_BNU_CHUNK(feBitSize)*3)*sizeof(BNU_CHUNK_T);

      *pSize = ecCtxSize            /* EC context */
              +ECGFP_ALIGNMENT
              +gfCtxSize            /* GF context */
              +GFP_ALIGNMENT
              +ecScratchBufferSize  /* *scratch buffer */
              +ecScratchBufferSize  /* should be enough for 2 tables */
              +CACHE_LINE_SIZE;

      return ippStsNoErr;
   }
}

/*F*
//    Name: ippsECCPGetSizeStd128r1
//          ippsECCPGetSizeStd128r2
//          ippsECCPGetSizeStd192r1
//          ippsECCPGetSizeStd224r1
//          ippsECCPGetSizeStd256r1
//          ippsECCPGetSizeStd384r1
//          ippsECCPGetSizeStd521r1
//          ippsECCPGetSizeStdSM2
*F*/
IPPFUN(IppStatus, ippsECCPGetSizeStd128r1, (int *pSize))
{
   return ippsECCPGetSize(128, pSize);
}

IPPFUN(IppStatus, ippsECCPGetSizeStd128r2, (int *pSize))
{
   return ippsECCPGetSize(128, pSize);
}

IPPFUN(IppStatus, ippsECCPGetSizeStd192r1, (int *pSize))
{
   return ippsECCPGetSize(192, pSize);
}

IPPFUN(IppStatus, ippsECCPGetSizeStd224r1, (int *pSize))
{
   return ippsECCPGetSize(224, pSize);
}


IPPFUN(IppStatus, ippsECCPGetSizeStd256r1, (int *pSize))
{
   return ippsECCPGetSize(256, pSize);
}

IPPFUN(IppStatus, ippsECCPGetSizeStd384r1, (int *pSize))
{
   return ippsECCPGetSize(384, pSize);
}

IPPFUN(IppStatus, ippsECCPGetSizeStd521r1, (int *pSize))
{
   return ippsECCPGetSize(521, pSize);
}

IPPFUN(IppStatus, ippsECCPGetSizeStdSM2, (int *pSize))
{
   return ippsECCPGetSize(256, pSize);
}


/*F*
//    Name: ippsECCPInit
//
// Purpose: Init ECC context.
//
// Returns:                   Reason:
//    ippStsNullPtrErr           NULL == pECC
//
//    ippStsSizeErr              2>feBitSize
//
//    ippStsNoErr                no errors
//
// Parameters:
//    feBitSize   size of field element (bits)
//    pECC        pointer to the ECC context
//
*F*/
IPPFUN(IppStatus, ippsECCPInit, (int feBitSize, IppsECCPState* pEC))
{
   /* test pEC pointer */
   IPP_BAD_PTR1_RET(pEC);
   /* use aligned EC context */
   pEC = (IppsECCPState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );

   /* test size of field element */
   IPP_BADARG_RET((2>feBitSize || feBitSize>EC_GFP_MAXBITSIZE), ippStsSizeErr);

   {
      /* size of GF context */
      //int gfCtxSize = cpGFpGetSize(feBitSize);
      int gfCtxSize = cpGFpGetSize(feBitSize, feBitSize+BITSIZE(BNU_CHUNK_T), GFP_POOL_SIZE);
      /* size of EC context */
      int ecCtxSize = cpGFpECGetSize(1, feBitSize);

      IppsGFpState* pGF = (IppsGFpState*)(IPP_ALIGNED_PTR((Ipp8u*)pEC+ecCtxSize, GFP_ALIGNMENT));
      BNU_CHUNK_T* pScratchBuffer = (BNU_CHUNK_T*)IPP_ALIGNED_PTR((Ipp8u*)pGF+gfCtxSize, CACHE_LINE_SIZE);

      /* set up contexts */
      IppStatus sts;
      do {
         sts = cpGFpInitGFp(feBitSize, pGF);
         if(ippStsNoErr!=sts) break;
         sts = ippsGFpECInit(pGF, NULL, NULL, pEC);
      } while (0);

      /* save scratch buffer pointer */
      ECP_SBUFFER(pEC) = pScratchBuffer;

      return sts;
   }
}

/*F*
//    Name: ippsECCPInitStd128r1
//          ippsECCPInitStd128r2
//          ippsECCPInitStd192r1
//          ippsECCPInitStd224r1
//          ippsECCPInitStd256r1
//          ippsECCPInitStd384r1
//          ippsECCPInitStd521r1
//          ippsECCPInitStdSM2
*F*/
IPPFUN(IppStatus, ippsECCPInitStd128r1, (IppsECCPState* pEC))
{
   return ippsECCPInit(128, pEC);
}

IPPFUN(IppStatus, ippsECCPInitStd128r2, (IppsECCPState* pEC))
{
   return ippsECCPInit(128, pEC);
}

IPPFUN(IppStatus, ippsECCPInitStd192r1, (IppsECCPState* pEC))
{
   return ippsECCPInit(192, pEC);
}

IPPFUN(IppStatus, ippsECCPInitStd224r1, (IppsECCPState* pEC))
{
   return ippsECCPInit(224, pEC);
}

IPPFUN(IppStatus, ippsECCPInitStd256r1, (IppsECCPState* pEC))
{
   return ippsECCPInit(256, pEC);
}

IPPFUN(IppStatus, ippsECCPInitStd384r1, (IppsECCPState* pEC))
{
   return ippsECCPInit(384, pEC);
}

IPPFUN(IppStatus, ippsECCPInitStd521r1, (IppsECCPState* pEC))
{
   return ippsECCPInit(521, pEC);
}

IPPFUN(IppStatus, ippsECCPInitStdSM2, (IppsECCPState* pEC))
{
   return ippsECCPInit(256, pEC);
}
