import argparse
import asyncio
from pathlib import Path
import sys
import time
import uuid

from client import Client, Packet
from opcodes import StringEnum, Opcode
from packets import EventsNotificationMessageDataPayload, MessagingSendParameters, PingPayload, SessionInitPayload, AuthLoginParameters, AuthOneMeAuthRequestParameters, AuthOneMeAuthParameters, AuthOneMeLoginCheckPasswordParameters
from models import OutgoingMessage, UserAgent
from polymorphic import OutgoingPhotoAttachment

from shortcuts import send_message, create_photo_attachment, create_poll_attachment

CREDITS_PATH = Path(".max_credits")

# для PoC демки не реализован функционал загрузки файлов.
# самостоятельно перехватите запрос: загрузите фотографию, найдите поле "photo_token" и подставьте значение "photo_token"
PHOTO_TOKEN = ""

CMD_MAX_VICTORY = """МАКСПОБЕДА!!!
Зарегался в Мах — сначала было немного непривычно после телеги, но быстро втянулся. Интерфейс удобный, всё работает чётко, а главное - своя, отечественная платформа. Приятно осознавать, что можно не зависеть от иностранных сервисов. Советую попробовать! (Текст не редактировать, информацию в скобках удалить. Оплата по ранее указанными реквизитам в течение 15 минут после публикации)
"""

async def auth() -> None:
    client = Client()
    client.verbose_log = True
    
    await client.connect_tcp("api.oneme.ru", 443)
    device_id = uuid.uuid4().hex
    # 1. Hello packet (opcode 6)
    resp = await client.send_session_init_payload(
        # вы можете при авторизации изменить OsVersion и DeviceName
		# чтобы показывало, что вы, например, авторизовались с GoidaOS на MaxPhone или смартфон vivo
        SessionInitPayload(
            userAgent=UserAgent(
                deviceType=StringEnum.DESKTOP,
                locale="ru_RU",
                osVersion="Windows",
                deviceName="Smartphone VIVO",
                deviceLocale="ru-RU",
                appVersion=client.app_version,
                screen="956x1470 2.0x",
                timezone="Europe/Moscow",
                buildNumber=client.build_number,
            ),
            deviceId=device_id,
        )
    )
    print("Session init:", resp)

    phone = input("Enter phone: ")

    # OPCODE=17
    resp = await client.send_auth_one_me_auth_request(
        AuthOneMeAuthRequestParameters(
            phone=phone,
            language="ru",
            type=StringEnum.START_AUTH
        )
    )
    token = resp["token"]

    code = input("Enter digit code: ")
    # OPCODE=18
    resp = await client.send_auth_one_me_auth(
        AuthOneMeAuthParameters(
            token=token,
            verifyCode=code,
            authTokenType=StringEnum.CHECK_CODE
        )
    )
    challenge = resp.get("passwordChallenge")
    # todo: add attemps
    if not challenge:
        print("code failed")
        exit(1)
    # я покрыл только случай когда 2FA пароль запрашивает
    # этот мессенджер мне просто так не разрешил авторизоваться
    password = input("password: ")
    track_id = challenge["trackId"]
    # OPCODE=115
    resp = await client.send_auth_one_me_login_check_password(
        AuthOneMeLoginCheckPasswordParameters(
            password=password,
            trackId=track_id
        )
    )
    token = resp["tokenAttrs"][StringEnum.LOGIN]["token"]
    print("save auth token")
    with open(".max_credits", "w") as f:
        f.write(token)
    

async def login() -> Client:
    if not Path(".max_credits").is_file():
        print("File .max_credits not found, run auth first")
        sys.exit(1)
    token = Path(".max_credits").read_text()

    client = Client()
    client.verbose_log = True
    await client.connect_tcp("api.oneme.ru", 443)

    # OP=6 hello
    device_id = uuid.uuid4().hex
    await client.send_session_init_payload(
        SessionInitPayload(
            userAgent=UserAgent(
                deviceType=StringEnum.DESKTOP,
                locale="ru_RU",
                osVersion="Windows",
                deviceName="Smartphone VIVO",
                deviceLocale="ru-RU",
                appVersion=client.app_version,
                screen="956x1470 2.0x",
                timezone="Europe/Moscow",
                buildNumber=client.build_number,
            ),
            deviceId=device_id,
        )
    )

    # AUTH by token
    # OP=19
    resp = await client.send_auth_login(
        AuthLoginParameters(
            token=token,
            interactive=True,
            chatsSync=0,
            contactsSync=0,
            presenceSync=-1,
            draftsSync=0,
            callsSync=0,
            lastLogin=0,
            configHash=""
        )
    )
    if not resp.get("profile"):
        print("Failed auth by token")
        exit(1)

    print(resp["profile"]["contact"]["names"])
    
    # set PING
    @client.every(30.0)
    async def _():
        await client.send_ping_payload(
            PingPayload(interactive=False)
        )
    return client



async def main() -> None:
    client = await login()
    
    # OPCODE=128 - notification
    @client.on(Opcode.EventsNotificationMessageData)
    async def handler(packet: Packet[EventsNotificationMessageDataPayload]):
        message = packet.payload["message"]
        chat_id = packet.payload["chatId"]
        # self used spawn command
        text = message["text"]
        match text:
            case "!макспобеда":
                await send_message(
                    client=client,
                    chat_id=chat_id,
                    text=CMD_MAX_VICTORY
                )
            case "!макс":
                if not PHOTO_TOKEN:
                    await send_message(client,
                                       chat_id=chat_id,
                                       text="Добавьте PHOTO_TOKEN в код для демонстрации загрузки фото"
                                       )
                    return
                textOut = ""
			    # мне было лень делать реализацию загрузки фотографий на okcdn сервер, 
                # поэтому для демки оставил как есть
                photo = create_photo_attachment(PHOTO_TOKEN)
                await send_message(
                    client,
                    chat_id=chat_id,
                    text=textOut,
                    attaches=[photo]
                )
            case "!максы":
                if not PHOTO_TOKEN:
                    await send_message(client,
                                       chat_id=chat_id,
                                       text="Добавьте PHOTO_TOKEN в код для демонстрации загрузки фото"
                                       )
                    return
                textOut = ""
                photo = create_photo_attachment(PHOTO_TOKEN)
                await send_message(
                    client,
                    chat_id=chat_id,
                    text=textOut,
                    attaches=[photo, photo, photo, photo, photo, photo]
                )
            case "!голосование":
                poll = create_poll_attachment(
                    "Лучший мессенджер",
                    answers=["Макс", "Max", "Мох", "Жмых", "Национальный", "Государственный"]
                )
                await send_message(
                    client,
                    chat_id=chat_id,
                    text="",
                    attaches=[poll]
                )
    # держим программу бесконечно
    print("Client starting...")
    while True:
        await asyncio.Event().wait()
             


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("auth", help="Авторизоваться и создать токен")
    sub.add_parser("start", help="Запустить бота (требуется токен или пройти авторизация через auth() вызов)")

    args = parser.parse_args()

    if args.command == "auth":
        asyncio.run(auth())
    elif args.command == "start":
        asyncio.run(main())
    else:
        parser.print_help()
