#!/usr/bin/env python3
import asyncio
import websockets
import json
import sys

async def health_check():
    try:
        async with websockets.connect('ws://127.0.0.1:8888') as ws:
            await ws.send(json.dumps({'type': 'health_check'}))
            resp = await ws.recv()
            data = json.loads(resp)
            return data.get('status') == 'OK'
    except Exception as e:
        print(f"Health check failed: {e}", file=sys.stderr)
        return False

if __name__ == "__main__":
    result = asyncio.run(health_check())
    sys.exit(0 if result else 1)