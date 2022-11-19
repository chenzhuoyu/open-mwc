#!/usr/bin/env python3
# -*- coding: utf-8 -8-

import sys
import logs
import miot
import asyncio

if __name__ == '__main__':
    logs.setup()
    asyncio.run(miot.MiotAppLoader.main(sys.argv[1:]))
