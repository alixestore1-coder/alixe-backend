from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# Tüm frontend portlarına izin ver
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tüm portlardan gelen istekleri kabul et
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"status": "ok"}
