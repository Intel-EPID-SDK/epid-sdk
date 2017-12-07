############################################################################
# Copyright 2017 Intel Corporation
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
# pylint: disable=locally-disabled, invalid-name, missing-docstring
"""msvc win32 compiler configuration for embedded
"""
from parts.config import ConfigValues, configuration


def map_default_version(env):
    return env['MSVC_VERSION']


config = configuration(map_default_version)

config.VersionRange(
    "7-*",
    append=ConfigValues(
        CCFLAGS=[
            # minimize size
            '/O1',
            # Use multi-thread static libc
            '/MT',
            # allow single line comment in C
            '/wd4001',
            # allow functions to auto inline
            '/wd4711',
            # allow compiler to append padding to structs
            '/wd4820',
            # allow while (0)
            '/wd4127',
            # whole program optimization
            #'/GL',
            # disable language extensions
            '/Za',
            # SDL: Stack-based Buffer Overrun Detection
            '/GS-',
            # SDL: Compiler settings validation
            #'/sdl-',
            # Compile using multiple processes
            '/MP',
            # treat all warnings as errors
            '/WX',
            '/Wall',
            '/nologo'
        ],
        CXXFLAGS=[
            '/EHsc',
            # disable RTTI
            '/GR-'
        ],
        LINKFLAGS=[
            # no default libraries
            '/NODEFAULTLIB',
            # prevent linker from references _main in dll
            '/NOENTRY',
            # elminiate unreferenced functions + data
            '/OPT:REF',
            # whole program optimization
            #'/LTCG',
            # SDL: Data Execution Prevention
            '/NXCOMPAT',
            # SDL: Image Randomization
            '/DYNAMICBASE',
            # SDL: Safe Exception Handling
            #'/SAFESEH', # not compatible with x64
            # treat linker warnings as errors
            '/WX',
            # target platform
            #'/MACHINE:X64',
            '/nologo'
        ],
        CPPDEFINES=['NDEBUG']))
