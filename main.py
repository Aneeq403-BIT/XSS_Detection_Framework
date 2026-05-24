from fastapi import FastAPI, BackgroundTasks
from pydantic import BaseModel
import joblib
import json
import logging
from datetime import datetime
from scanner import EnterpriseScanner

# Setup SIEM-style logging (Outputting to terminal and a log file)
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger("SIEM_Logger")

# 1. Initialize API
app = FastAPI(
    title="Enterprise XSS Detection Microservice",
    description="Dual-Engine AI & Sandbox framework for scalable XSS mitigation.",
    version="3.0"
)

# 2. Load Models & Scanner
print("Booting Enterprise Detection Engines...")
try:
    model = joblib.load("xss_model_rf.pkl")
    vectorizer = joblib.load("vectorizer_rf.pkl")
except:
    print("WARNING: Run train_model.py first to generate .pkl files!")

scanner = EnterpriseScanner()

# 3. Enterprise JSON Ingestion Format
class LogPayload(BaseModel):
    source_ip: str
    endpoint: str
    method: str
    raw_payload: str

def send_to_siem(alert_data: dict):
    """Simulates streaming alerts to an Enterprise SIEM like Splunk."""
    log_entry = json.dumps(alert_data)
    logger.info(f"[SIEM ALERT] -> {log_entry}")
    # In a real enterprise, this is where Kafka/Splunk integration goes!

@app.post("/api/v1/analyze")
async def analyze_traffic(data: LogPayload, background_tasks: BackgroundTasks):
    raw_text = data.raw_payload
    timestamp = datetime.utcnow().isoformat()
    
    # PRE-PROCESSING: Recursive Decoding
    cleaned_text = scanner.recursive_decode(raw_text)
    
    # LAYER 1: Rule Engine (Instant Block)
    if scanner.rule_engine_scan(cleaned_text):
        response = {
            "timestamp": timestamp, "ip": data.source_ip, "status": "BLOCKED",
            "threat_score": 90, "engine": "Heuristics_Rule_Engine", "payload": cleaned_text
        }
        background_tasks.add_task(send_to_siem, response)
        return response
        
    # LAYER 2: AI Machine Learning Engine
    vectorized_input = vectorizer.transform([cleaned_text])
    ai_prediction = model.predict(vectorized_input)[0]
    
    if ai_prediction == 1:
        # LAYER 3: Dynamic Sandbox Verification (The Ultimate Decider)
        is_executable = await scanner.headless_sandbox_check(cleaned_text)
        
        if is_executable:
            response = {
                "timestamp": timestamp, "ip": data.source_ip, "status": "BLOCKED",
                "threat_score": 100, "engine": "AI_Sandbox_Verified", "payload": cleaned_text
            }
        else:
            response = {
                "timestamp": timestamp, "ip": data.source_ip, "status": "FLAGGED",
                "threat_score": 75, "engine": "AI_Model_Heuristics", "payload": cleaned_text
            }
        background_tasks.add_task(send_to_siem, response)
        return response
            
    # Clean Traffic
    return {"status": "ALLOWED", "threat_score": 0, "engine": "Passed_All"}