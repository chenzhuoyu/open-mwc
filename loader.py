#!/usr/bin/env python3
# -*- coding: utf-8 -8-

import os
import sys
import miot
import asyncio
import logging
import coloredlogs

LEVEL_NAMES = {
    'critical' : logging.CRITICAL,
    'fatal'    : logging.FATAL,
    'error'    : logging.ERROR,
    'warn'     : logging.WARNING,
    'warning'  : logging.WARNING,
    'info'     : logging.INFO,
    'debug'    : logging.DEBUG,
}

# get the log level from environment
name = os.getenv('LOG_LEVEL', 'info')
level = LEVEL_NAMES.get(name.lower())

# check for log level
if level is None:
    print('* error: invalid log level', repr(name), file = sys.stderr)
    sys.exit(1)

# install the logger, and start the app
coloredlogs.install(level, fmt = '%(asctime)s %(name)s [%(levelname)s] %(message)s', milliseconds = True)
asyncio.run(miot.MiotAppLoader.main(sys.argv[1:]))
