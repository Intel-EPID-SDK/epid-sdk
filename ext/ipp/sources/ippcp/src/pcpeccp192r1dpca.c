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
//     EC over Prime Finite Field (setup/retrieve domain parameters)
//
//  Contents:
//     ippsECCPSetStd192r1()
*/
#include "owncp.h"
#include "pcpeccp.h"


/*
// Set EC192r1 parameters
*/
IPPFUN(IppStatus, ippsECCPSetStd192r1, (IppsECCPState* pEC))
{
   /* test pEC */
   IPP_BAD_PTR1_RET(pEC);
   /* use aligned EC context */
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );

   /* set domain parameters */
   return ECCPSetDP(ippsGFpMethod_p192r1(),
                        BITS_BNU_CHUNK(192), secp192r1_p,
                        BITS_BNU_CHUNK(192), secp192r1_a,
                        BITS_BNU_CHUNK(192), secp192r1_b,
                        BITS_BNU_CHUNK(192), secp192r1_gx,
                        BITS_BNU_CHUNK(192), secp192r1_gy,
                        BITS_BNU_CHUNK(192), secp192r1_r,
                        secp192r1_h,
                        pEC);
}

IPPFUN(IppStatus, ippsECCPBindGxyTblStd192r1,(IppsECCPState* pEC))
{
   /* test pEC */
   IPP_BAD_PTR1_RET(pEC);
   /* use aligned EC context */
   pEC = (IppsGFpECState*)( IPP_ALIGNED_PTR(pEC, ECGFP_ALIGNMENT) );
   IPP_BADARG_RET(!ECP_TEST_ID(pEC), ippStsContextMatchErr);

   ECP_PREMULBP(pEC) = gfpec_precom_nistP192r1_fun();

   return ippStsNoErr;
}
