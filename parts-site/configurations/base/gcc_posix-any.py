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

"""default gcc compiler configuration
"""
from parts.config import configuration


def map_default_version(env):
    return env['GCC_VERSION']


def enable_sanitizers(env, recover):
    """ Enable sanitizers
    Args:
        recover: Enable sanitizers recovery from errors found.
    """
    version_minimum = 6
    version_major = int(map_default_version(env).partition('.')[0])
    if version_major >= version_minimum:
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
    else:
        raise RuntimeError(
            'Build with sanitizers is only supported for '
            'GCC version greater than {}'.format(version_minimum))


def post_process_func(env):
    if env.get('sanitizers', False):
        enable_sanitizers(env, env.get('sanitizers_recover', False))


config = configuration(map_default_version, post_process_func)

config.VersionRange("*")
