# pylint: disable=import-error,missing-docstring,wrong-import-order,invalid-name
import parts.tools.IntelCommon
import parts.tools.Common
import SCons.Util
import SCons.Warnings
import os

from parts.tools.IntelCommon import Intelc


def generate(env):
    Intelc.MergeShellEnv(env)
    is_windows = env['TARGET_PLATFORM'].OS == 'win32'
    if is_windows:
        env['CC'] = parts.tools.Common.toolvar(
            'icl', ('icc', 'icl', 'intelc'), env=env)
        env['CXX'] = parts.tools.Common.toolvar(
            'icl', ('icpc', 'icl', 'icc', 'intelc'), env=env)
        env['LINK'] = parts.tools.Common.toolvar(
            'xilink', ('xilink', ), env=env)
        env['AR'] = parts.tools.Common.toolvar('xilib', ('xilib', ), env=env)
    else:
        env['CC'] = parts.tools.Common.toolvar(
            'icc', ('icl', 'icc', 'intelc'), env=env)
        env['CXX'] = parts.tools.Common.toolvar(
            'icpc', ('icpc', 'icl', 'icc', 'intelc'), env=env)
        # Don't reset LINK here;
        # use smart_link which should already be here from link.py.
        #env['LINK']      = '$CC'
        env['AR'] = parts.tools.Common.toolvar('xiar', ('xiar', ), env=env)
        env['LD'] = parts.tools.Common.toolvar(
            'xild', ('xild', ), env=env)  # not used by default

    if is_windows:
        # Look for license file dir
        # in system environment, and default location.
        envlicdir = os.environ.get("INTEL_LICENSE_FILE", '').split(os.pathsep)
        defaultlicdir = r'C:\Program Files\Common Files\Intel\Licenses'

        licdir = None
        for ld in envlicdir:
            if ld and os.path.exists(ld):
                licdir = ld
                break
        if licdir is None:
            licdir = defaultlicdir
            if not os.path.exists(licdir):

                class ICLLicenseDirWarning(SCons.Warnings.Warning):
                    pass

                SCons.Warnings.enableWarningClass(ICLLicenseDirWarning)
                SCons.Warnings.warn(
                    ICLLicenseDirWarning, "Intel license dir was not found."
                    "  Tried using the INTEL_LICENSE_FILE environment variable"
                    " (%s) and the default path (%s)."
                    "  Using the default path as a last resort." %
                    (envlicdir, defaultlicdir))
        env['ENV']['INTEL_LICENSE_FILE'] = licdir


def exists(env):
    return Intelc.Exists(env)


# vim: set et ts=4 sw=4 ai ft=python :
