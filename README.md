Markdown# AI Vulnerability Triage & CVSS Engine

Gemini API destekli zafiyet analiz motoru; güvenlik açıklarını CVSS v3.1 standardında değerlendirir, temel risk skorunu hesaplar, bulguları JSONL formatında loglar ve **Wazuh SIEM** ile canlı entegrasyon sağlar.

---

## Mimari

```text
+---------------------------------------+
|  Pentest / Bug Bounty Zafiyet Raporu  |
+---------------------------------------+
                    |
                    v
+---------------------------------------+
|     FastAPI / Gemini AI Engine        |
|  - CVSS v3.1 Vektör & Skor Hesaplama  |
|  - JSON Formatında Log Üretimi       |
+---------------------------------------+
                    |
                    v (Docker Volume Mount)
+---------------------------------------+
|         /var/log/cvss_ai.log          |
+---------------------------------------+
                    |
                    v
+---------------------------------------+
|            Wazuh Manager              |
|  - Rule ID 100100: AI Event Match     |
|  - Rule ID 100101: High/Critical Alert|
+---------------------------------------+
                    |
                    v
+---------------------------------------+
|       Wazuh Indexer & Dashboard       |
|  - Canlı Tehdit Avı ve Görselleştirme |
+---------------------------------------+
ÖzelliklerOtomatik CVSS v3.1 Hesaplama: Doğal dilde yazılmış zafiyet açıklamalarından resmi CVSS vektör dizesini ve temel skorunu türetir.JSONL Loglama: SIEM araçlarının doğrudan parse edebileceği yapılandırılmış JSON log formatı.Uçtan Uca Wazuh Entegrasyonu: Özel decoder ve kural setleriyle (Rule 100100, 100101) kritik riskleri anında tetikler.Kalıcı Docker Yapılandırması: Host log dosyasını Wazuh Manager konteynerine bağlayan volume eşlemesi.Ön KoşullarPython 3.10+Docker & Docker ComposeÇalışan bir Wazuh Single-Node Docker StackGoogle AI Studio (Gemini) API AnahtarıKurulum1. Depoyu Klonlayın ve Bağımlılıkları YükleyinBashgit clone [https://github.com/kullaniciadi/cvss-ai-lab.git](https://github.com/kullaniciadi/cvss-ai-lab.git)
cd cvss-ai-lab

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
2. Ortam Değişkenlerini Ayarlayın.env.example dosyasını .env olarak kopyalayın ve API anahtarınızı girin:Bashcp .env.example .env
.env dosya içeriği:Kod snippet'iGEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
LOG_FILE_PATH=/var/log/cvss_ai.log
APP_HOST=0.0.0.0
APP_PORT=8000
Wazuh SIEM & Docker Yapılandırması1. Log Dosyasını Host Üzerinde OluşturunBashsudo touch /var/log/cvss_ai.log
sudo chmod 666 /var/log/cvss_ai.log
2. Docker Compose Volume Eşlemesini EkleyinWazuh kurulum dizininizdeki (wazuh-docker/single-node/docker-compose.yml) wazuh.manager servisine host log dosyasını bağlayın:YAML  wazuh.manager:
    image: wazuh/wazuh-manager:4.9.0
    hostname: wazuh.manager
    restart: always
    volumes:
      - /var/log/cvss_ai.log:/var/log/cvss_ai.log:ro
      - wazuh_etc:/var/ossec/etc
      - wazuh_logs:/var/ossec/logs
      - wazuh_queue:/var/ossec/queue
      - wazuh_var_multigroups:/var/ossec/var/multigroups
      - wazuh_integrations:/var/ossec/integrations
      - /etc/localtime:/etc/localtime:ro
3. Wazuh Manager Log Okuma ve Kural TanımlarıAşağıdaki komutları çalıştırarak dosya izlemeyi ve kural setlerini Wazuh Manager'a ekleyin:Bash# Log toplama bloğunu ossec.conf'a ekleyin
docker exec -i single-node-wazuh.manager-1 sed -i '/<\/ossec_config>/i \  <localfile>\n    <log_format>json<\/log_format>\n    <location>/var/log/cvss_ai.log</location>\n  <\/localfile>' /var/ossec/etc/ossec.conf

# Özel CVSS tespit kurallarını local_rules.xml dosyasına yazdırın
docker exec -i single-node-wazuh.manager-1 bash -c 'cat << "EOF" > /var/ossec/etc/rules/local_rules.xml
<group name="cvss_ai,">
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="event_type">^ai_cvss_assessment$</field>
    <description>AI CVSS Security Assessment Event</description>
  </rule>

  <rule id="100101" level="10">
    <if_sid>100100</if_sid>
    <field name="severity">^Critical$\vert{}^High$</field>
    <description>High/Critical CVSS Risk Detected by AI Lab</description>
  </rule>
</group>
EOF'

# Wazuh servisini yeniden başlatın
docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
ÇalıştırmaGeliştirme SunucusuBashsource venv/bin/activate
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
API belgeleri ve etkileşimli Swagger UI: http://localhost:8000/docsAPI KullanımıSağlık KontrolüBashcurl http://localhost:8000/health
Zafiyet AnaliziBashcurl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "report_text": "Kullanıcı profil fotoğrafı yükleme alanında dosya uzantı kontrolü yapılmıyor, sunucuya PHP dosyası yüklenip uzaktan kod çalıştırılabiliyor.",
    "source": "pentest"
  }'
Örnek API YanıtıJSON{
  "status": "success",
  "data": {
    "vuln_title": "Unrestricted File Upload Remote Code Execution",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
    "base_score": 8.8,
    "severity": "High",
    "metrics": {
      "attack_vector": "NETWORK",
      "attack_complexity": "LOW",
      "privileges_required": "LOW",
      "user_interaction": "NONE",
      "scope": "UNCHANGED",
      "confidentiality": "HIGH",
      "integrity": "HIGH",
      "availability": "HIGH"
    }
  }
}
Yapılandırma ParametreleriDeğişkenTipVarsayılanAçıklamaGEMINI_API_KEYstring(Zorunlu)Google GenAI API anahtarıGEMINI_MODELstringgemini-2.5-flashDeğerlendirme yapacak modelLOG_FILE_PATHstring/var/log/cvss_ai.logJSONL loglarının yazılacağı yolAPP_HOSTstring0.0.0.0FastAPI dinleme adresiAPP_PORTinteger8000FastAPI dinleme portuGüvenlik NotuBu araç yetkili sızma testi (penetration testing), bug bounty ve güvenlik operasyonları süreçlerini hızlandırmak için geliştirilmiştir. API anahtarlarını, hassas müşteri verilerini veya doğrulanmamış zafiyet loglarını genel erişime açık depolara yüklemeyin.
<ElicitationsGroup message="Şimdi ne yapmak istersiniz?">
<Elicitation label="Create a systemd unit file for FastAPI deployment" query="Create a systemd service unit file for the FastAPI app" query_intent="CLICKABLE_SUGGESTION" />
<Elicitation label="Draft unit tests for CVSS calculation and logging" query="Draft pytest unit tests for FastAPI CVSS triage endpoint" query_intent="CLICKABLE_SUGGESTION" />
<Elicitation label="Add Dockerfile to containerize the FastAPI application" query="Create a Dockerfile and docker-compose entry for the FastAPI service" query_intent="CLICKABLE_SUGGESTION" />
</ElicitationsGroup>
