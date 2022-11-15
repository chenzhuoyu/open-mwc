#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
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

def setup():
    name = os.getenv('LOG_LEVEL', 'info')
    level = LEVEL_NAMES.get(name.lower())

    # check for log level
    if level is None:
        level = logging.INFO
        print('* error: invalid log level, default to INFO', repr(name), file = sys.stderr)

    # configure the logger
    coloredlogs.install(
        fmt          = '%(asctime)s %(name)s [%(levelname)s] %(message)s',
        level        = level,
        milliseconds = True,
    )
