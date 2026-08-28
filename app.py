import json
import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from cvss import CVSS3
from google import genai
from google.genai import types
import uvicorn

load_dotenv()

app = FastAPI(
    title="AI Vulnerability Triage & CVSS Engine",
    description="LLM tabanlı zafiyet raporu analizi ve SIEM loglama servisi",
    version="1.0.0"
)

GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.6-flash")
LOG_FILE_PATH = Path(os.getenv("LOG_FILE_PATH", "logs/cvss_ai.log"))

class ReportRequest(BaseModel):
    report_text: str = Field(..., example="Dosya yükleme alanında uzantı kontrolü yapılmıyor. Sisteme doğrudan PHP yüklenerek uzaktan kod çalıştırılabiliyor.")
    source: str = Field(default="api_webhook", example="bugbounty")

class ReportResponse(BaseModel):
    title: str
    cvss_vector: str
    base_score: float
    severity: str
    metrics: dict

def analyze_vulnerability_with_llm(report_text: str) -> dict:
    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
    prompt = f"""
Aşağıdaki zafiyet bildirim raporunu analiz et ve CVSS v3.1 temel metriklerini belirle.
Rapor:
\"\"\"{report_text}\"\"\"

Çıktıyı yalnızca ve kesinlikle aşağıdaki JSON şemasına uygun ver:
{{
  "title": "Zafiyet Başlığı",
  "attack_vector": "NETWORK | ADJACENT_NETWORK | LOCAL | PHYSICAL",
  "attack_complexity": "LOW | HIGH",
  "privileges_required": "NONE | LOW | HIGH",
  "user_interaction": "NONE | REQUIRED",
  "scope": "UNCHANGED | CHANGED",
  "confidentiality": "NONE | LOW | HIGH",
  "integrity": "NONE | LOW | HIGH",
  "availability": "NONE | LOW | HIGH"
}}
"""
    response = client.models.generate_content(
        model=GEMINI_MODEL,
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json"
        )
    )
    return json.loads(response.text)

def generate_cvss_vector(data: dict) -> str:
    av = {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P"}.get(data.get("attack_vector"), "N")
    ac = {"LOW": "L", "HIGH": "H"}.get(data.get("attack_complexity"), "L")
    pr = {"NONE": "N", "LOW": "L", "HIGH": "H"}.get(data.get("privileges_required"), "N")
    ui = {"NONE": "N", "REQUIRED": "R"}.get(data.get("user_interaction"), "N")
    s  = {"UNCHANGED": "U", "CHANGED": "C"}.get(data.get("scope"), "U")
    c  = {"NONE": "N", "LOW": "L", "HIGH": "H"}.get(data.get("confidentiality"), "N")
    i  = {"NONE": "N", "LOW": "L", "HIGH": "H"}.get(data.get("integrity"), "N")
    a  = {"NONE": "N", "LOW": "L", "HIGH": "H"}.get(data.get("availability"), "N")

    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

def log_to_wazuh(payload: dict):
    LOG_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload) + "\n")

@app.post("/api/v1/analyze", response_model=ReportResponse)
async def analyze_report(request: ReportRequest):
    if not request.report_text.strip():
        raise HTTPException(status_code=400, detail="Rapor metni boş olamaz.")

    try:
        analysis = analyze_vulnerability_with_llm(request.report_text)
        vector = generate_cvss_vector(analysis)
        cvss_calc = CVSS3(vector)
        base_score = float(cvss_calc.base_score)
        severity = cvss_calc.severities()[0]

        log_entry = {
            "event_type": "ai_cvss_assessment",
            "source": request.source,
            "vuln_title": analysis.get("title", "Unknown Vulnerability"),
            "cvss_vector": vector,
            "base_score": base_score,
            "severity": severity,
            "metrics": analysis
        }

        log_to_wazuh(log_entry)

        return ReportResponse(
            title=analysis.get("title", "Unknown"),
            cvss_vector=vector,
            base_score=base_score,
            severity=severity,
            metrics=analysis
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail="Analiz işlemi sırasında bir hata oluştu.") from e

@app.get("/health")
def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=os.getenv("APP_HOST", "0.0.0.0"),
        port=int(os.getenv("APP_PORT", "8000")),
    )