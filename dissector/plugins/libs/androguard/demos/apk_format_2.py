#!/usr/bin/env python

import sys

PATH_INSTALL = "./"
sys.path.append( PATH_INSTALL )

from androguard.core.bytecodes import dvm
from dissector.plugins.libs.androguard.androguard.core.bytecodes import apk

TEST = "./apks/crash/mikecc/e0399fdd481992bc049b6e9d765da7f007f89875.apk"

a = apk.APK(TEST, zipmodule=2)
a.show()

j = dvm.DalvikVMFormat( a.get_dex() )

# SHOW CLASS (verbose)
#j.show()
