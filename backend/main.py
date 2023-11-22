from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from Crypto.Cipher import AES
from redis import asyncio as aioredis
from datetime import datetime, timedelta
from starlette.responses import HTMLResponse
from starlette import status
from typing import Annotated

from fastapi.websockets import WebSocket, WebSocketDisconnect
import os


def get_timestamp():
    return (datetime.utcnow() + timedelta(hours=2)).strftime("%Y-%m-%d %H:%M:%S")


def unpad(data):
    padding = data[-1]
    if padding < 1 or padding > AES.block_size:
        return b""
    if data[-padding:] != bytes([padding]) * padding:
        return b""
    return data[:-padding]


key = os.environ["KEY"].encode("utf-8")
iv = os.environ["IV"].encode("utf-8")
cookie_val = os.environ["COOKIE"]
username = os.environ["USERNAME"]
password = os.environ["PASSWORD"]

app = FastAPI()

security = HTTPBasic()

redis = None
html_content = None


@app.on_event("startup")
async def startup_event():
    global redis
    global html_content
    redis = await aioredis.from_url(
        f"redis://localhost", encoding="utf-8", decode_responses=True
    )

    html_content = open("index.html", "r").read().replace("CHANGE_THIS", cookie_val)


@app.on_event("shutdown")
async def shutdown_event():
    global redis
    if redis is not None:
        await redis.close()


@app.get("/")
async def root(credentials: Annotated[HTTPBasicCredentials, Depends(security)]):
    if not (credentials.username == username) or not (credentials.password == password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )

    return HTMLResponse(content=html_content, status_code=200)


@app.websocket("/verysecret/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    cookie = await websocket.receive_text()
    if cookie != "my_cookie=" + cookie_val:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

    requests_ps = await redis.lrange(f"requests:ps", 0, 2000)
    requests_fr = await redis.lrange(f"requests:fr", 0, 2000)
    requests_fwr = await redis.lrange(f"requests:fwr", 0, 2000)

    await websocket.send_json(
        {"ps": requests_ps[::-1], "fr": requests_fr[::-1], "fwr": requests_fwr[::-1]}
    )

    pubsub = redis.pubsub()
    await pubsub.subscribe(f"pubsub")
    async for message in pubsub.listen():
        if message["type"] == "message":
            the_type, the_msg = message["data"].split("~", maxsplit=1)
            await websocket.send_json({the_type: [the_msg]})


@app.get("/verysecret/get_all_ps")
async def get_all_ps(credentials: Annotated[HTTPBasicCredentials, Depends(security)]):
    if not (credentials.username == username) or not (credentials.password == password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    data = await redis.lrange("requests:ps", 0, -1)
    return {"data": data}


@app.get("/verysecret/get_all_fr")
async def get_all_fr(credentials: Annotated[HTTPBasicCredentials, Depends(security)]):
    if not (credentials.username == username) or not (credentials.password == password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    data = await redis.lrange("requests:fr", 0, -1)
    return {"data": data}


@app.get("/verysecret/get_all_fwr")
async def get_all_fwr(credentials: Annotated[HTTPBasicCredentials, Depends(security)]):
    if not (credentials.username == username) or not (credentials.password == password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
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

    uvicorn.run(app, host="0.0.0.0", port=8900)
