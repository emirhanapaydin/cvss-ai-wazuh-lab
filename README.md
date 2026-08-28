# AI Vulnerability Triage & CVSS Engine

Gemini ile zafiyet raporlarını analiz eden, CVSS v3.1 temel skorunu hesaplayan ve JSONL formatında loglayan FastAPI servisi.

## Gereksinimler

- Python 3.10+
- Google Gemini API anahtarı

## Kurulum

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

`.env` içindeki `GEMINI_API_KEY` değerini kendi Gemini API anahtarınızla değiştirin. `.env` dosyası Git'e dahil edilmemelidir.

## Çalıştırma

```bash
source venv/bin/activate
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

API dokümantasyonu için `http://localhost:8000/docs` adresini açın.

## Endpointler

### Sağlık kontrolü

```bash
curl http://localhost:8000/health
```

### Zafiyet analizi

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H 'Content-Type: application/json' \
  -d '{
    "report_text": "Dosya yükleme alanında uzantı kontrolü yapılmıyor.",
    "source": "bugbounty"
  }'
```

Yanıt; zafiyet başlığını, CVSS v3.1 vektörünü, temel skoru, önem seviyesini ve belirlenen metrikleri içerir.

## Yapılandırma

| Değişken | Varsayılan | Açıklama |
| --- | --- | --- |
| `GEMINI_API_KEY` | Yok | Gemini API anahtarı |
| `GEMINI_MODEL` | `gemini-3.6-flash` | Kullanılacak Gemini modeli |
| `LOG_FILE_PATH` | `logs/cvss_ai.log` | JSONL log dosyası |
| `APP_HOST` | `0.0.0.0` | Örnek sunucu host değeri |
| `APP_PORT` | `8000` | Örnek sunucu port değeri |

Loglar varsayılan olarak yerel `logs/` klasörüne yazılır. Wazuh entegrasyonu için `LOG_FILE_PATH` değerini Wazuh tarafından izlenen bir dosyaya yönlendirebilirsiniz.

## Güvenlik notu

Bu servis yalnızca yetkili güvenlik testleri ve zafiyet triage süreçleri için kullanılmalıdır. API anahtarlarını kaynak koduna veya Git geçmişine eklemeyin.
