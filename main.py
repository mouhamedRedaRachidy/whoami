from fastapi import FastAPI

app = FastAPI()


@app.get("/")
def home():
    return {"message": "Bonjour Reda !"}


@app.get("/health")
def health():
    return {"status": "ok"}