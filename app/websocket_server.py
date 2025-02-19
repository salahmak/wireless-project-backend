import asyncio
import json
import websockets
from app.config import settings


class AlertWebsocketServer:
    def __init__(self):
        self.connections = set()

    async def register(self, websocket):
        self.connections.add(websocket)
        try:
            await websocket.wait_closed()
        finally:
            self.connections.remove(websocket)

    async def broadcast_alert(self, alert_data):
        if not self.connections:
            return

        message = json.dumps(alert_data)
        websockets_to_remove = set()

        for websocket in self.connections:
            try:
                await websocket.send(message)
            except websockets.exceptions.WebSocketException:
                websockets_to_remove.add(websocket)

        # Remove any closed connections
        self.connections -= websockets_to_remove

    async def start_server(self):
        async with websockets.serve(
            self.register, "localhost", settings.WEBSOCKET_PORT
        ):
            await asyncio.Future()  # run forever
