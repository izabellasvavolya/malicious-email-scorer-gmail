from fastapi import FastAPI
from pydantic import BaseModel

from analyzer import analyze_email


app = FastAPI(
    title="Malicious Email Scorer API",
    description="Explainable heuristic analysis of potentially malicious emails.",
    version="1.0.0"
)


class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str


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
        subject=email.subject,
        body=email.body
    )