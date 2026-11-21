#!/usr/bin/env python3
"""DEMO ONLY: plain TCP pass-through (no WAF, no TLS) used by the "dvwa-direct"
service to show the unprotected app in a browser. Usage: tcp_forward.py LISTEN_PORT HOST PORT"""
import asyncio
import sys

LPORT, HOST, PORT = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])


async def pipe(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()


async def handle(cr, cw):
    try:
        ur, uw = await asyncio.open_connection(HOST, PORT)
    except OSError:
        cw.close()
        return
    await asyncio.gather(pipe(cr, uw), pipe(ur, cw))


async def main():
    server = await asyncio.start_server(handle, "0.0.0.0", LPORT)
    print(f"[dvwa-direct] forwarding :{LPORT} -> {HOST}:{PORT} (NO WAF)", flush=True)
    async with server:
        await server.serve_forever()

asyncio.run(main())
