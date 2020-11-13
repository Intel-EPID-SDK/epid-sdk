# pylint: disable=unused-wildcard-import,missing-docstring,import-error,multiple-imports,line-too-long
from parts.tools import intelc
#if windows
import parts.tools.IntelCommon.intelc_win32, parts.tools.IntelCommon.intelc_win32_91, parts.tools.IntelCommon.intelc_win32_12
#if posix
import parts.tools.IntelCommon.intelc_posix
