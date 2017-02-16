import os
import sys

def fexecvp(args):
    pid = os.fork()
    if pid == 0:
        os.execvp(args[0],args)
        sys.exit(0)
        return ~0
    else:
        return pid
