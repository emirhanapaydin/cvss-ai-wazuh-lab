
# AI CVSS ENGINE

Projenin ne yaptığını, hangi problemi çözdüğünü anlatan kısa ve net 1-2 cümlelik açıklama.

## System Architecture

```text
┌─────────────────────────────────┐
│   Pentest / Bug Bounty Report   │
└────────────────┬────────────────┘
                 │ (HTTP POST)
                 ▼
┌─────────────────────────────────┐
│       FastAPI AI Engine         │
│  • Gemini CVSS v3.1 Inference   │
│  • JSON Schema Serialization    │
└────────────────┬────────────────┘
                 │ (Append JSONL)
                 ▼
┌─────────────────────────────────┐
│      /var/log/cvss_ai.log       │
└────────────────┬────────────────┘
                 │ (Docker Volume Mount)
                 ▼
┌─────────────────────────────────┐
│          Wazuh Manager          │
│  • Rule 100100: AI Event Match  │
│  • Rule 100101: Critical Alert  │
└────────────────┬────────────────┘
                 │ (Filebeat / TLS)
                 ▼
┌─────────────────────────────────┐
│    Wazuh Indexer & Dashboard    │
│  • Real-time Threat Hunting     │
└─────────────────────────────────┘
```
## Features

* Automated CVSS v3.1 Scoring: Generates standard vector strings and base metrics from unstructured vulnerability reports.

* Structured JSONL Logging: Emits machine-readable audit logs for SIEM log collectors.

* Custom Wazuh Decoders & Rules: Built-in detection logic prioritizing High and Critical severity findings (Rule 100100, Rule 100101).

* Containerized Integration: Synchronizes log streaming across host and Docker environments via read-only bind mounts.

# Getting Started

Projeyi yerel ortamınızda çalıştırmak için aşağıdaki adımları izleyin.

### Prerequisites

* Python 3.10+

* Docker & Docker Compose

* Wazuh Single-Node Deployment

* Google Gemini API Key

### Local Setup

#### 1. Clone the repository:

```bash
git clone https://github.com/emirhanapaydin/cvss-ai-wazuh-lab.git
cd cvss-ai-wazuh-lab
```
#### 2. Create and activate a virtual environment:

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip
python3 -m venv venv
source venv/bin/activate
```
#### 3. Install dependencies:

```bash
pip install -r requirements.txt
```

#### 4.Configure environment variables:
```bash
cp .env.example .env
```
Update .env with your credentials:

```text
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash
LOG_FILE_PATH=/var/log/cvss_ai.log
APP_HOST=0.0.0.0
APP_PORT=8000
```
## Wazuh Installation

### 1. Prepare System Requirements
```bash
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### 2. Install Docker and Docker Compose

```bash
sudo apt update && sudo apt install -y ca-certificates curl gnupg lsb-release git
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker
```
### 3. Clone Wazuh Docker Repository & Generate Certificates
```bash
if [ ! -d "wazuh-docker" ]; then
  git clone https://github.com/wazuh/wazuh-docker.git -b v4.9.0 --depth=1
fi

cd wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
```
### 4. Start the Wazuh Stack
```bash
docker compose up -d
```
## Wazuh SIEM & Docker Integration

### 1. Configure Volume Bind Mount
Ensure /var/log/cvss_ai.log is mounted into the wazuh.manager service in docker-compose.yml:

```bash
python3 -c '
path = "docker-compose.yml"
with open(path, "r") as f:
    lines = f.readlines()

mount_entry = "      - /var/log/cvss_ai.log:/var/log/cvss_ai.log:ro\n"

if mount_entry not in lines:
    for i, line in enumerate(lines):
        if "wazuh_etc:/var/ossec/etc" in line:
            lines.insert(i, mount_entry)
            break
    with open(path, "w") as f:
        f.writelines(lines)
'
```
### 2. Apply Wazuh Ingestion & Rule Configurations
Inject the log collection block and custom security rules into the Wazuh Manager container:
```bash
docker exec -i single-node-wazuh.manager-1 sed -i '/<\/ossec_config>/i \  <localfile>\n    <log_format>json<\/log_format>\n    <location>/var/log/cvss_ai.log</location>\n  </localfile>' /var/ossec/etc/ossec.conf

docker exec -i single-node-wazuh.manager-1 bash -c 'cat << "EOF" > /var/ossec/etc/rules/local_rules.xml
<group name="cvss_ai,">
  <rule id="100100" level="3">
    <decoded_as>json</decoded_as>
    <field name="event_type">^ai_cvss_assessment$</field>
    <description>AI CVSS Security Assessment Event</description>
  </rule>

  <rule id="100101" level="10">
    <if_sid>100100</if_sid>
    <field name="severity">^Critical$|^High$</field>
    <description>High/Critical CVSS Risk Detected by AI Lab</description>
  </rule>
</group>
EOF'

docker exec -it single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```
### 3. Restart Docker
```bash
cd ~/cvss-ai-wazuh-lab/wazuh-docker/single-node
docker compose down
docker compose up -d
### 4. Initialize the Log File on Host
```
```bash
sudo touch /var/log/cvss_ai.log
sudo chmod 666 /var/log/cvss_ai.log
```
## Running the Application
Start the FastAPI application with Uvicorn:
```bash
source venv/bin/activate
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```
### API Reference
#### Health Check
```bash
curl http://localhost:8000/health
```
#### Analyze Finding
```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "report_text": "Unrestricted file upload vulnerability in the profile picture endpoint allows uploading PHP scripts, leading to remote code execution.",
    "source": "pentest"
  }'
```
#### Example Response
```json
{
  "status": "success",
  "data": {
    "vuln_title": "Unrestricted File Upload Leading to Remote Code Execution",
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
```
