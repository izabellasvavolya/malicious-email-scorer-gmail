from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()


class EmailRequest(BaseModel):
    sender: str
    subject: str
    body: str


@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/analyze")
def analyze_email(email: EmailRequest):
    return {
        "score": 50,
        "verdict": "Suspicious",
        "reasons": [
            "Backend connection successful"
        ]
    }