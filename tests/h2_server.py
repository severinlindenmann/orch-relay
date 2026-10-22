"""A minimal local HTTP/2 (cleartext, prior knowledge) server for the real APNs client path: it records
each request's pseudo-headers, headers and body and answers from a script, over the `h2` state machine.
It speaks HTTP/2 only, so a successful exchange proves the client did not fall back to HTTP/1.1."""

import asyncio
import json
import threading

import h2.config
import h2.connection
import h2.events


class H2Server:
    def __init__(self, answer=None):
        self.requests = []  # dicts: method, path, headers, body, connection
        self.connections = 0
        self.peak = 0
        self.active = 0
        self.answer = answer or (lambda request: (200, None))
        self.hold = None  # an asyncio.Event the handler waits on before answering (set in the loop)
        self.url = None
        self.loop = None
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        self.loop = asyncio.new_event_loop()
        self.loop.run_until_complete(self.serve())

    async def serve(self):
        self.stop = asyncio.Event()
        server = await asyncio.start_server(self.connection, "127.0.0.1", 0)
        self.url = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
        self.ready.set()
        await self.stop.wait()
        server.close()
        await server.wait_closed()

    def start(self):
        self.thread.start()
        assert self.ready.wait(5)
        return self

    def close(self):
        self.loop.call_soon_threadsafe(self.stop.set)
        self.thread.join(5)

    async def connection(self, reader, writer):
        self.connections += 1
        number = self.connections
        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=False))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        pending = {}
        try:
            while data := await reader.read(65535):
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.RequestReceived):
                        pending[event.stream_id] = {
                            "headers": [(k.decode(), v.decode()) for k, v in event.headers],
                            "body": b"",
                            "connection": number,
                        }
                    elif isinstance(event, h2.events.DataReceived):
                        pending[event.stream_id]["body"] += event.data
                        conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    elif isinstance(event, h2.events.StreamEnded):
                        request = pending.pop(event.stream_id)
                        asyncio.ensure_future(self.respond(conn, writer, event.stream_id, request))
                writer.write(conn.data_to_send())
        except (ConnectionError, h2.exceptions.ProtocolError):
            pass
        finally:
            writer.close()

    async def respond(self, conn, writer, stream_id, request):
        pseudo = dict(h for h in request["headers"] if h[0].startswith(":"))
        request.update(
            method=pseudo[":method"],
            path=pseudo[":path"],
            headers={k: v for k, v in request["headers"] if not k.startswith(":")},
        )
        self.requests.append(request)
        self.active += 1
        self.peak = max(self.peak, self.active)
        if self.hold is not None:
            await self.hold.wait()
        self.active -= 1
        status, payload = self.answer(request)
        body = json.dumps(payload).encode() if payload is not None else b""
        conn.send_headers(
            stream_id,
            [(":status", str(status)), ("content-length", str(len(body)))],
            end_stream=not body,
        )
        if body:
            conn.send_data(stream_id, body, end_stream=True)
        writer.write(conn.data_to_send())
