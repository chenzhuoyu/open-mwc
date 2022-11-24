#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time

from logs import Logger
from enum import IntEnum
from typing import Callable
from asyncio import Future
from functools import cached_property

class CameraSIID(IntEnum):
    Control             = 2
    Misc                = 3
    DetectionMisc       = 4
    Detection           = 5
    OTA                 = 6
    # GoogleSupport     = 7     # not implemented
    # AlexaSupport      = 8     # not implemented

class StationSIID(IntEnum):
    CameraControl       = 2
    StorageSD           = 3
    StorageUSB          = 4
    StorageControl      = 5
    OTA                 = 6

class OTAPIID(IntEnum):
    Progress            = 1     # u8    = 100
    State               = 2     # str   = 'idle'

class StoragePIID(IntEnum):
    Enabled             = 1     # bool  = False
    TotalSize           = 2     # u64   = 0
    FreeSize            = 3     # u64   = 0
    UsedSize            = 4     # u64   = 0
    Status              = 5     # i32   = 0

class DetectionPIID(IntEnum):
    Enabled             = 1     # bool  = True
    RecordInterval      = 2     # u16   = 30
    RecordSensitivity   = 3     # u16   = 100

class CameraMiscPIID(IntEnum):
    LED                 = 1     # bool  = True
    LiveStream          = 2     # u8    = 0
    Distortion          = 3     # bool  = True
    BatteryLevel        = 4     # u8    = 100
    Resolution          = 5     # u8    = 0
    RSSI                = 6     # i16   = -100
    Online              = 7     # bool  = False
    PowerFreq           = 8     # u8    = 50
    BatteryVoltage      = 100   # virtual PIID

class DetectionMiscPIID(IntEnum):
    RecordFreq          = 1     # u16   = 0
    RecordLimit         = 2     # u16   = 10
    Enabled             = 3     # bool  = True

class CameraControlPIID(IntEnum):
    PowerSwitch         = 1     # bool  = True
    Flip                = 2     # u16   = 0
    NightVision         = 3     # u8    = 2
    OSDTimestamp        = 4     # bool  = True
    WDR                 = 5     # bool  = True

class StorageControlPIID(IntEnum):
    StorageSwitch       = 1     # bool  = True
    Type                = 2     # u8    = 0
    LightIndicator      = 3     # bool  = True

SIID = int | CameraSIID | StationSIID
PIID = int | OTAPIID | StoragePIID | CameraControlPIID | StorageControlPIID

class Property:
    ty   : type
    log  : Logger
    siid : SIID
    piid : PIID

    def __init__(self, siid: SIID, piid: PIID, ty: type):
        self.ty   = ty
        self.log  = Logger.for_name('props')
        self.siid = siid
        self.piid = piid

    def __repr__(self) -> str:
        return '(%s) %s' % (self.ty.__name__, self.name)

    @cached_property
    def name(self) -> str:
        return '%s.%s' % (self.siid.name, self.piid.name)

    async def _do_read(self) -> object:
        raise NotImplementedError('read()')

    async def _do_write(self, value: object):
        raise NotImplementedError('write()', value)

    def _do_update(self, value: object):
        raise NotImplementedError('update()', value)

    async def read(self) -> object:
        t0 = time.monotonic()
        ret = await self._do_read()
        self.log.debug('Read property %s returns %r in %.3fms.' % (self.name, ret, (time.monotonic() - t0) * 1000))
        return ret

    async def write(self, value: object):
        if not isinstance(value, self.ty):
            raise TypeError('%s expected for %s.%s, got %s' % (self.ty, self.name, type(value)))
        else:
            t0 = time.monotonic()
            await self._do_write(value)
            self.log.debug('Wrote property %s with value %r in %.3fms.' % (self.name, value, (time.monotonic() - t0) * 1000))

    def update(self, value: object):
        if not isinstance(value, self.ty):
            raise TypeError('%s expected for %s.%s, got %s' % (self.ty, self.name, type(value)))
        else:
            t0 = time.monotonic()
            self._do_update(value)
            self.log.debug('Updated property %s with value %r in %.3fms.' % (self.name, value, (time.monotonic() - t0) * 1000))

class FuncProperty(Property):
    getter: Callable[[], Future[object]] | None
    setter: Callable[[object], Future[None]] | None

    def __init__(self,
        siid   : SIID,
        piid   : PIID,
        ty     : type,
        getter : Callable[[], Future[object]] | None = None,
        setter : Callable[[object], Future[None]] | None = None,
    ):
        self.getter = getter
        self.setter = setter
        super().__init__(siid, piid, ty)

    async def _do_read(self) -> object:
        if self.getter is None:
            raise PermissionError('property %s is not readable' % self.name)
        else:
            return await self.getter()

    async def _do_write(self, value: object):
        if self.setter is None:
            raise PermissionError('property %s is not writable' % self.name)
        else:
            await self.setter(value)

    def _do_update(self, value: object):
        raise PermissionError('Update property %s with value %r is not supported.' % (self.name, value))

class ValueProperty(Property):
    log   : Logger
    value : object

    def __init__(self, siid: SIID, piid: PIID, value: object):
        self.log   = Logger.for_name('props')
        self.value = value
        super().__init__(siid, piid, type(value))

    async def _do_read(self) -> object:
        return self.value

    async def _do_write(self, value: object):
        self.log.warning('Writting %r to read-only property %s, discarded.' % (value, self.name))

    def _do_update(self, value: object):
        self.value = value

class MutableProperty(Property):
    value  : object
    notify : Callable[[Property, object], Future] | None

    def __init__(self,
        siid   : SIID,
        piid   : PIID,
        init   : object,
        notify : Callable[[Property, object], Future] | None = None,
    ):
        self.value = init
        self.notify = notify
        super().__init__(siid, piid, type(init))

    async def _notify(self, value: object):
        if self.notify:
            await self.notify(self, value)

    async def _do_read(self) -> object:
        return self.value

    async def _do_write(self, value: object):
        await self._notify(value)
        self.value = value

    def _do_update(self, value: object):
        self.value = value

class Properties:
    log   : Logger
    props : dict[SIID, dict[PIID, Property]]

    def __init__(self, *props: Property):
        self.log   = Logger.for_name('props')
        self.props = {}
        self.register(*props)

    def __getitem__(self, key: tuple[SIID, PIID]) -> Property:
        siid, piid = key
        return self.find(siid, piid)

    def __setitem__(self, key: tuple[SIID, PIID], value: object):
        siid, piid = key
        self.find(siid, piid).update(value)

    def find(self, siid: SIID, piid: PIID) -> Property:
        if siid not in self.props:
            raise ValueError('no such SIID ' + str(siid))
        elif piid not in self.props[siid]:
            raise ValueError('no such PIID %s for SIID %s' % (piid, siid))
        else:
            return self.props[siid][piid]

    def register(self, *props: Property):
        for p in props:
            self.log.debug('Registering property: %s' % p.name)
            self.props.setdefault(p.siid, {})[p.piid] = p