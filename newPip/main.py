#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys

from ryu.cmd import manager


def main():
    sys.argv.append('--ofp-tcp-listen-port')
    sys.argv.append('6633')
    sys.argv.append('monitor.py')
    sys.argv.append('--verbose')
    sys.argv.append('--enable-debugger')
    manager.main()
    print("after main")

if __name__ == '__main__':
    main()


