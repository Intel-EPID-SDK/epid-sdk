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
# pylint: disable=locally-disabled, invalid-name, missing-docstring
"""default clang compiler configuration
"""
from parts.config import configuration


def map_default_version(env):
    return env['CLANG_VERSION']


def enable_sanitizers(env, recover):
    """ Enable sanitizers
    Args:
        recover: Enable sanitizers recovery from errors found.
    """
    env.AppendUnique(CCFLAGS=[
        '-g',
        '-fsanitize=address,undefined',
        '-fno-sanitize=alignment',
        '-fno-sanitize=shift',
        '-fno-omit-frame-pointer'])
    env.AppendUnique(LINKFLAGS=[
        '-fsanitize=address,undefined'])
    if recover:
        env.AppendUnique(CCFLAGS=[
            '-fsanitize-recover=all',
            '-fsanitize-recover=address'])


def enable_fuzzer(env):
    """Enable instrumentation for libFuzzer"""
    major = int(env['CLANG_VERSION'].partition('.')[0])
    version_minimum = 5
    if major >= version_minimum:
        env.AppendUnique(
            CPPDEFINES=['FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION'])
        env.AppendUnique(CCFLAGS=[
            '-g', '-fsanitize=fuzzer', '-fprofile-instr-generate',
            '-fcoverage-mapping'
        ])
        env.AppendUnique(LINKFLAGS=[
            '-fsanitize-coverage=trace-pc-guard', '-fprofile-instr-generate'
        ])
        env.AppendUnique(FUZZLINKFLAGS=['-fsanitize=fuzzer'])
    else:
        raise RuntimeError(
            "Fuzzing is only supported for CLANG version greater "
            "than {}. Current CLANG version is {}".format(
                version_minimum, env.get('CLANG_VERSION', 'unknown')))


def post_process_func(env):
    if env.get('sanitizers', False):
        enable_sanitizers(env, env.get('sanitizers_recover', False))
    if env.get('fuzzer', False):
        enable_fuzzer(env)


config = configuration(map_default_version, post_process_func)

config.VersionRange("*")
