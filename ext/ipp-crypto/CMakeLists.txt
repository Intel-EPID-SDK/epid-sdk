#===============================================================================
# Copyright 2019-2020 Intel Corporation
# All Rights Reserved.
#
# If this  software was obtained  under the  Intel Simplified  Software License,
# the following terms apply:
#
# The source code,  information  and material  ("Material") contained  herein is
# owned by Intel Corporation or its  suppliers or licensors,  and  title to such
# Material remains with Intel  Corporation or its  suppliers or  licensors.  The
# Material  contains  proprietary  information  of  Intel or  its suppliers  and
# licensors.  The Material is protected by  worldwide copyright  laws and treaty
# provisions.  No part  of  the  Material   may  be  used,  copied,  reproduced,
# modified, published,  uploaded, posted, transmitted,  distributed or disclosed
# in any way without Intel's prior express written permission.  No license under
# any patent,  copyright or other  intellectual property rights  in the Material
# is granted to  or  conferred  upon  you,  either   expressly,  by implication,
# inducement,  estoppel  or  otherwise.  Any  license   under such  intellectual
# property rights must be express and approved by Intel in writing.
#
# Unless otherwise agreed by Intel in writing,  you may not remove or alter this
# notice or  any  other  notice   embedded  in  Materials  by  Intel  or Intel's
# suppliers or licensors in any way.
#
#
# If this  software  was obtained  under the  Apache License,  Version  2.0 (the
# "License"), the following terms apply:
#
# You may  not use this  file except  in compliance  with  the License.  You may
# obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
#
#
# Unless  required  by   applicable  law  or  agreed  to  in  writing,  software
# distributed under the License  is distributed  on an  "AS IS"  BASIS,  WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#
# See the   License  for the   specific  language   governing   permissions  and
# limitations under the License.
#===============================================================================
cmake_minimum_required(VERSION 3.1)

project("ipp-crypto")

AUX_SOURCE_DIRECTORY(sources/ippcp SRC)

add_library(ipp-crypto
        ${SRC}
        )

if(MSVC)
else()
    target_compile_options(ipp-crypto PRIVATE -Wno-unused-function
            -Wno-unused-variable
            -Wno-attributes
            -Wno-unused-but-set-variable
            -Wno-strict-aliasing
            -Wno-sign-compare
            -Wno-parentheses)

endif()
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_ARCH_IA32")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_IPP_DEBUG")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_IPP_C99")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_IPP_v50_")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_PX")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_ABL_")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DISABLE_ECP_SM2_")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DISABLE_ALG_SHA224_")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DISABLE_ALG_SHA512_224_")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DISABLE_ALG_MD5_")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DISABLE_ALG_SM3_")
add_definitions(-D_NO_IPP_DEPRECATED)

target_include_directories(ipp-crypto
        PUBLIC include
        PRIVATE sources/include
        )