import os
import motor.motor_asyncio
client = motor.motor_asyncio.AsyncIOMotorClient(
    os.environ["MONGO_HOST"],
    port=int(os.environ["MONGO_PORT"]),
    username=os.environ["MONGO_USERNAME"],
    password=os.environ["MONGO_PASSWORD"],
)