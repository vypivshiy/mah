import time
from typing import TYPE_CHECKING


from models import OutgoingMessage
from polymorphic import OutgoingPhotoAttachment, OutgoingPollAttachment, PollAnswer
from packets import MessagingSendParameters
from opcodes import StringEnum


if TYPE_CHECKING:
    from client import Client



def create_photo_attachment(photo_token: str) -> OutgoingPhotoAttachment:
    return OutgoingPhotoAttachment(_type=StringEnum.PHOTO, photoToken=photo_token)

def create_poll_attachment(title: str,
                           answers: list[str]):
    answers = [PollAnswer(text=i) for i in answers]
    
    return OutgoingPollAttachment(
        _type=StringEnum.POLL,
        title=title,
        answers=answers,
        settings=4 # ???
    )

async def send_message(
        client: "Client",
        chat_id: int,
        text: str,
        attaches: list[OutgoingPhotoAttachment | OutgoingPollAttachment] | None = None
        ):
    attaches = attaches or []
    cid = int(time.time())
    
    await client.send_messaging_send(
                    MessagingSendParameters(
                        chatId=chat_id,
                        notify=True,
                        message=OutgoingMessage(
                            cid=cid,
                            text=text,
                            elements=[],
                            attaches=attaches
                        )
                    )
                )