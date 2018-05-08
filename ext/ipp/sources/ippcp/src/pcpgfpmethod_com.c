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
//     GF(p) methods
//
*/
#include "owncp.h"

#include "pcpgfpmethod.h"

/* available pre-defined general methos */
IPPFUN( const IppsGFpMethod*, ippsGFpMethod_pArb, (void) )
{
   static IppsGFpMethod method = {
      cpID_Prime,
      0,
      NULL,
      NULL
   };
      method.arith = gsArithGFp();
   return &method;
}
