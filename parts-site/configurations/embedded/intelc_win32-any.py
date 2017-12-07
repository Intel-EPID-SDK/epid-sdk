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

"""Intel win32 compiler configurations release
"""
from parts.config import ConfigValues, configuration

def map_default_version(env):
    return env['INTELC_VERSION']

config = configuration(map_default_version)

config.VersionRange("7-*",
                    append=ConfigValues(
                        CCFLAGS=[
                            # Compile using multiple processes
                            '/MP',
                            # SDL: Stack-based Buffer Overrun Detection
                            '/GS-',
                            # minimize size
                            '/O1',
                            # allow non standart comment in C
                            '/wd991',
                            # typedef forward with the same name
                            '/wd344',
                            # disable language extensions
                            '/Za',
                            # Use multi-thread static libc
                            '/MT',
                            # treat all warnings as errors
                            '/Wall',
                            '/WX',
                            '/nologo'],
                        CXXFLAGS=[
                            '/EHsc',
                            # disable RTTI
                            '/GR-'],
                        LINKFLAGS=[
                            # no default libraries
                            '/NODEFAULTLIB',
                            # prevent linker from references _main in dll
                            '/NOENTRY',
                            # elminiate unreferenced functions + data
                            '/OPT:REF',
                            # SDL: Data Execution Prevention
                            '/NXCOMPAT',
                            # SDL: Image Randomization
                            '/DYNAMICBASE',
                            # treat linker warnings as errors
                            '/WX',
                            '/nologo'
                        ],
                        CPPDEFINES=['NDEBUG']
                    )
                   )
