#!/usr/bin/python3
from ctypes import *

if __name__ == '__main__':
    target_dll = 'kernel32.dll'
    target_func = b'WinExec'
    target_func2 = b'ExitProcess'

    kernel32 = windll.LoadLibrary('kernel32.dll')
    dll = windll.LoadLibrary(target_dll)

    kernel32.GetProcAddress.restype = (c_void_p)
    kernel32.GetProcAddress.argtypes = (c_void_p, c_char_p)
    func = kernel32.GetProcAddress( dll._handle, target_func)
    func2 = kernel32.GetProcAddress( dll._handle, target_func2)
    print('## Address %s(%s) : 0x%08x'%(target_dll, target_func, func))
    print('## Address %s(%s) : 0x%08x'%(target_dll, target_func2, func))