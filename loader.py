#!/usr/bin/env python3
# -*- coding: utf-8 -8-

import sys
import miio
import asyncio
import logging
import coloredlogs

LOG_FMT   = '%(asctime)s %(name)s [%(levelname)s] %(message)s'
LOG_LEVEL = logging.DEBUG

async def test():
    with open('packets.gdbdump') as fp:
        idx = 0
        host = ''
        date = ''
        name = '(n/a)'
        state = 'host'
        domain = ''
        for line in fp.read().splitlines():
            line = line.strip()
            if not line:
                continue
            if line.startswith('Breakpoint'):
                date = ''
                name = line.split()[-2]
                continue
            if date == '':
                date = '[' + line.strip() + ']'
                continue
            if not line.startswith('$'):
                continue
            if name == 'd0_tls_open':
                val = line.split(maxsplit = 3)[-1]
                if state == 'host':
                    host = val
                    state = 'domain'
                    continue
                elif state == 'domain':
                    domain = val
                    state = 'port'
                    continue
                elif state == 'port':
                    name = '(n/a)'
                    state = 'host'
                    print(date, 'd0_tls_open: host', host, 'domain', domain, 'port', val)
                    print()
                    continue
                else:
                    raise RuntimeError()
            line = line.split('=', 1)[1].strip()
            def gendata():
                for v in line[1:-1].split(','):
                    v = [x.strip() for x in v.split()]
                    x = int(v[0], 16)
                    if len(v) == 1:
                        yield x
                    else:
                        yield from [x] * int(v[2])
            rbuf = bytes(gendata())
            data = miio.StreamReader()
            data.feed_data(rbuf)
            try:
                pkt = await miio.Packet.read_from(data)
                print(date, 'Seq %d:' % idx, name, pkt.ty, pkt.data)
            except ValueError as e:
                print(e)
                print(date, 'Seq %d:' % idx, name, rbuf)
            print()
            idx += 1
            name = '(n/a)'

async def main():
    cfg = miio.MiioAppConfig(*sys.argv)
    host, port = await cfg.resolve()
    conn = await cfg.connect(host, port)
    await conn.run_forever()

if __name__ == '__main__':
    coloredlogs.install(fmt = LOG_FMT, level = LOG_LEVEL, milliseconds = True)
    asyncio.run(main())
