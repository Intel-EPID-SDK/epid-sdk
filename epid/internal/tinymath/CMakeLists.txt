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

set(DEFS_INCLUDE_DIR "../../defs/include")

set(SRC_FILES
        src/efq.c
        src/efq2.c
        src/fp.c
        src/fq.c
        src/fq2.c
        src/fq6.c
        src/fq12.c
        src/hashwrap.c
        src/pairing.c
        src/serialize.c
        src/sha256.c
        src/sha384.c
        src/sha512.c
        src/sha512_256.c
        src/sha512_base.c
        src/vli.c
        )

set(TEST_FILES
        test/cmp-testhelper.cc
        test/efq2-test.cc
        test/efq-test.cc
        test/fp-test.cc
        test/fq2-test.cc
        test/fq6-test.cc
        test/fq12-test.cc
        test/fq-test.cc
        test/main-testhelper.cc
        test/pairing-test.cc
        test/serialize-test.cc
        test/sha256-test.cc
        test/sha384-test.cc
        test/sha512-test.cc
        test/sha512_256-test.cc
        test/vli-test.cc
        )

add_library(tinymath ${SRC_FILES})
target_include_directories(tinymath
        PUBLIC include
        PRIVATE ${DEFS_INCLUDE_DIR}
        )
target_link_libraries(tinymath tinystdlib)

enable_testing()
add_executable(tinymath_test
        ${SRC_FILES}
        ${TEST_FILES}
        )
target_include_directories(tinymath_test
        PUBLIC include
        )
target_link_libraries(tinymath_test gtest_main)
target_link_libraries(tinymath_test tinystdlib)
target_link_libraries(tinymath_test testhelper)
add_test(tinymath_test tinymath_test)
