#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import typing
import logging

try:
    import coloredlogs
except ImportError:
    coloredlogs = None

TRACE  = 9
FORMAT = '%(asctime)s %(name)s [%(levelname)s] %(message)s'

class Logger(logging.Logger):
    def trace(self, msg, *args, **kwargs):
        if self.isEnabledFor(TRACE):
            self._log(TRACE, msg, args, **kwargs)

    @staticmethod
    def for_name(name: str) -> 'Logger':
        return typing.cast(Logger, logging.getLogger(name))

# install a new log level TRACE
logging.addLevelName(TRACE, 'TRACE')
logging.setLoggerClass(Logger)

# install the style for colored logs
if coloredlogs is not None:
    style = coloredlogs.DEFAULT_LEVEL_STYLES
    style.update(trace = style['spam'])

# level names to level mapping
LEVEL_NAMES = {
    'critical' : logging.CRITICAL,
    'fatal'    : logging.FATAL,
    'error'    : logging.ERROR,
    'warn'     : logging.WARNING,
    'warning'  : logging.WARNING,
    'info'     : logging.INFO,
    'debug'    : logging.DEBUG,
    'trace'    : TRACE,
}

def setup():
    name = os.getenv('LOG_LEVEL', 'info')
    level = LEVEL_NAMES.get(name.lower())

    # check for log level
    if level is None:
        level = logging.INFO
        print('* error: invalid log level, default to INFO', repr(name), file = sys.stderr)

    # configure the logger
    if coloredlogs is not None:
        coloredlogs.install(level, fmt = FORMAT, milliseconds = True)
