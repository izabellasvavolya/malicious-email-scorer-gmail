from fastapi import FastAPI
from pydantic import BaseModel, Field

from analyzer import analyze_email


app = FastAPI(
    title="Malicious Email Scorer API",
    description="Explainable analysis of potentially malicious emails.",
    version="1.0.0"
)


class AttachmentInfo(BaseModel):
    name: str = ""
    content_type: str = ""
    size: int = 0


class EmailRequest(BaseModel):
    sender: str
    reply_to: str = ""
    authentication_results: str = ""
    subject: str
    body: str
    attachments: list[AttachmentInfo] = Field(default_factory=list)


@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "Malicious Email Scorer"
    }


@app.post("/analyze")
def analyze(email: EmailRequest):
    return analyze_email(
        sender=email.sender,
        reply_to=email.reply_to,
        authentication_results=email.authentication_results,
        subject=email.subject,
        body=email.body,
        attachments=[
            attachment.model_dump()
            for attachment in email.attachments
        ]
    )