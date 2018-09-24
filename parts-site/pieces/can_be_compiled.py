############################################################################
# Copyright 2018 Intel Corporation
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
############################################################################
# pylint: disable=import-error

"""module to check if given toolchain supports C++11"""

import os.path
from parts import api
from SCons.Script import Configure


def can_be_compiled(env, code):
    """Check if the code can be compiled"""
    conf = Configure(env)
    if not conf.TryCompile(code, '.cc'):
        if not os.path.isfile('.sconf_temp/conftest_0.cc'):
            env.PrintError(
                "TryCompile failed. Rerun the scons with '--config=force' parameter"
            )
        res = False
    else:
        res = True
    env = conf.Finish()
    return res


CPP11_CODE = """
#include <stdint.h>
#include <memory>
int main(void) {
    std::shared_ptr<int>* ptr(nullptr);
    (void)ptr;
    uint32_t res = 6;
    uint32_t buf[10]{1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    for (auto u32 : buf) {
        res += u32;
    }
    return 0;
}"""
api.register.add_global_object('CPP11_CODE', CPP11_CODE)
api.register.add_global_object('CanBeCompiled', can_be_compiled)
