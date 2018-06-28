import ctypes
import os.path
import platform

RESOURCE_DIR = os.path.dirname(os.path.abspath(__file__)) + '/resources'

if platform.system() == "Windows":
    ctypes.CDLL(RESOURCE_DIR + '/libeay32.dll')
    ctypes.CDLL(RESOURCE_DIR + '/ssleay32.dll')

import rsa
