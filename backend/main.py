from fastapi import FastAPI, Request
from Crypto.Cipher import AES
from aioredis import from_url
from datetime import datetime, timedelta
from starlette.responses import FileResponse
from starlette import status

from fastapi.websockets import WebSocket, WebSocketDisconnect


def get_timestamp():
    return (datetime.utcnow() + timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S")


def unpad(data):
    padding = data[-1]
    if padding < 1 or padding > AES.block_size:
        return b""
    if data[-padding:] != bytes([padding]) * padding:
        return b""
    return data[:-padding]


key = b"4cd50b3a7f8921e6"
iv = b"39871eac6f5024db"

app = FastAPI()

redis = None


@app.on_event("startup")
async def startup_event():
    global redis
    redis = await from_url(
        f"redis://localhost", encoding="utf-8", decode_responses=True
    )


@app.on_event("shutdown")
async def shutdown_event():
    global redis
    if redis is not None:
        await redis.close()


@app.get("/")
async def root(request: Request):
    cookie_value = request.cookies.get("my_cookie")
    if cookie_value != "8c61ed9702ba54f3":
        return {"message": "Hello, World!"}

    return FileResponse("index.html")


@app.websocket("/verysecret/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    cookie = await websocket.receive_text()
    if cookie != "my_cookie=8c61ed9702ba54f3":
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    requests_ps = await redis.lrange(f"requests:ps", 0, 2000)
    requests_fr = await redis.lrange(f"requests:fr", 0, 2000)
    requests_fwr = await redis.lrange(f"requests:fwr", 0, 2000)

    await websocket.send_json(
        {"ps": requests_ps, "fr": requests_fr, "fwr": requests_fwr}
    )

    pubsub = redis.pubsub()
    await pubsub.subscribe(f"pubsub")
    async for message in pubsub.listen():
        if message["type"] == "message":
            the_type, the_msg = message["data"].split("~", maxsplit=1)
            await websocket.send_json({the_type: [the_msg]})


@app.get("/verysecret/get_all_ps")
async def get_all_ps(request: Request):
    cookie_value = request.cookies.get("my_cookie")
    if cookie_value != "8c61ed9702ba54f3":
        return {"message": "Hello, World!"}

    data = await redis.lrange("requests:ps", 0, -1)
    return {"data": data}


@app.get("/verysecret/get_all_fr")
async def get_all_fr(request: Request):
    cookie_value = request.cookies.get("my_cookie")
    if cookie_value != "8c61ed9702ba54f3":
        return {"message": "Hello, World!"}

    data = await redis.lrange("requests:fr", 0, -1)
    return {"data": data}


@app.get("/verysecret/get_all_fwr")
async def get_all_fwr(request: Request):
    cookie_value = request.cookies.get("my_cookie")
    if cookie_value != "8c61ed9702ba54f3":
        return {"message": "Hello, World!"}

    data = await redis.lrange("requests:fwr", 0, -1)
    return {"data": data}


@app.post("/ingest/{machine_uid}")
async def ingest(machine_uid: str, request: Request):
    data = await request.body()
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = aes.decrypt(data)
    decrypted_data = unpad(decrypted_data)

    try:
        data = decrypted_data.decode("utf-8")
        for line in data.split("\n"):
            if line:
                line = get_timestamp() + "-" + machine_uid + "-" + line
                await redis.publish(f"pubsub", "ps~" + line)
                await redis.lpush(f"requests:ps", line)
    except UnicodeDecodeError:
        pass

    return {"message": "ok"}


@app.post("/ingest_fr/{machine_uid}")
async def ingest_fr(machine_uid: str, request: Request):
    data = await request.body()
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = aes.decrypt(data)
    decrypted_data = unpad(decrypted_data)

    try:
        data = decrypted_data.decode("utf-8")
        for line in data.split("\n"):
            if line:
                line = get_timestamp() + "-" + machine_uid + "-" + line
                await redis.publish(f"pubsub", "fr~" + line)
                await redis.lpush(f"requests:fr", line)
    except UnicodeDecodeError:
        pass

    return {"message": "ok"}


@app.post("/ingest_fwr/{machine_uid}")
async def ingest_fwr(machine_uid: str, request: Request):
    data = await request.body()
    aes = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = aes.decrypt(data)
    decrypted_data = unpad(decrypted_data)

    try:
        data = decrypted_data.decode("utf-8")
        for line in data.split("\n"):
            if line:
                line = get_timestamp() + "-" + machine_uid + "-" + line
                await redis.publish(f"pubsub", "fwr~" + line)
                await redis.lpush(f"requests:fwr", line)
    except UnicodeDecodeError:
        pass

    return {"message": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=5000)
