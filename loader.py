#!/usr/bin/env python3
# -*- coding: utf-8 -8-

import sys
import miot
import asyncio
import logging
import coloredlogs

LOG_FMT   = '%(asctime)s %(name)s [%(levelname)s] %(message)s'
LOG_LEVEL = logging.DEBUG

if __name__ == '__main__':
    coloredlogs.install(fmt = LOG_FMT, level = LOG_LEVEL, milliseconds = True)
    asyncio.run(miot.MiotAppLoader.main(sys.argv[1:]))
