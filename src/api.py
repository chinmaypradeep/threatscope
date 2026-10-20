import asyncio
import json
import logging
import os
import joblib
import pandas as pd
import numpy as np
import shap
import httpx
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import redis.asyncio as redis

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("threatscope_api")

app = FastAPI(title="ThreatScope API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379")
REDIS_STREAM = "live_network_flows"

# Globals
model = None
explainer = None
redis_client = None
active_connections = []

EXPECTED_FEATURES = [
    'Flow Duration', 'Fwd Pkt Len Max', 'Fwd Header Len',
    'Bwd Header Len', 'Flow IAT Mean', 'Flow IAT Min',
    'Flow IAT Max', 'Fwd Pkts/s', 'Bwd Pkts/s',
    'Flow Pkts/s', 'Init Fwd Win Byts', 'Init Bwd Win Byts',
    'Fwd Seg Size Min', 'bwd_packet_rate', 'fwd_packet_rate'
]

def load_ml_components():
    global model, explainer, EXPECTED_FEATURES
    try:
        model_path = os.path.join(os.path.dirname(__file__), "..", "models", "random_forest_model.pkl")
        model = joblib.load(model_path)
        explainer = shap.TreeExplainer(model)
        
        if hasattr(model, 'feature_names_in_'):
            EXPECTED_FEATURES = list(model.feature_names_in_)
            
        logger.info("Loaded Random Forest model and SHAP explainer successfully.")
    except Exception as e:
        logger.error(f"Failed to load ML models: {e}")

async def get_geoip(ip_address):
    # Basic private IP check
    if ip_address.startswith("192.168.") or ip_address.startswith("10.") or ip_address.startswith("127."):
        return {"lat": None, "lon": None, "country": "Local", "city": "LocalNetwork"}
    
    # In production, use a premium API key or local MaxMind DB
    # For now, using ipinfo.io free tier
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(f"https://ipinfo.io/{ip_address}/json", timeout=2.0)
            if response.status_code == 200:
                data = response.json()
                loc = data.get("loc", ",").split(",")
                if len(loc) == 2 and loc[0] != "":
                    return {
                        "lat": float(loc[0]),
                        "lon": float(loc[1]),
                        "country": data.get("country", "Unknown"),
                        "city": data.get("city", "Unknown")
                    }
    except Exception as e:
        pass
    
    return {"lat": None, "lon": None, "country": "Unknown", "city": "Unknown"}

async def process_flow_stream():
    """Background task to read from Redis, run ML model, and broadcast to WebSockets."""
    global redis_client
    try:
        redis_client = redis.from_url(REDIS_URL)
        await redis_client.ping()
        logger.info("Connected to Redis successfully.")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        return

    last_id = "$"
    
    while True:
        try:
            # Read new entries from the stream
            response = await redis_client.xread({REDIS_STREAM: last_id}, count=10, block=1000)
            
            if response:
                for stream, messages in response:
                    for msg_id, msg_data in messages:
                        last_id = msg_id
                        try:
                            # Extract flow record
                            record_str = msg_data.get(b"data")
                            if record_str:
                                record = json.loads(record_str.decode('utf-8'))
                                await analyze_and_broadcast(record)
                        except Exception as e:
                            logger.error(f"Error processing message {msg_id}: {e}")
        except Exception as e:
            logger.error(f"Error reading from Redis: {e}")
            await asyncio.sleep(2)

async def analyze_and_broadcast(record, target_connections=None):
    if not model:
        return
        
    targets = target_connections if target_connections is not None else active_connections
    if not targets:
        return

    src_ip = record.get("Src IP", "192.168.1.100")
    dst_ip = record.get("Dst IP", "8.8.8.8")
    
    # Create DataFrame for model
    df_features = pd.DataFrame([record])
    
    # Ensure expected features exist
    for col in EXPECTED_FEATURES:
        if col not in df_features.columns:
            df_features[col] = 0
            
    df_selected = df_features[EXPECTED_FEATURES]
    
    # Predict
    probabilities = model.predict_proba(df_selected)[0]
    attack_prob = probabilities[1]
    is_anomaly = attack_prob > 0.5
    
    if is_anomaly:
        # Calculate SHAP only for anomalies to save CPU
        shap_vals = explainer.shap_values(df_selected)
        if isinstance(shap_vals, list):
            shap_vals = shap_vals[1]
            
        shap_vals = shap_vals.flatten()
        if len(shap_vals) == 2 * len(EXPECTED_FEATURES):
            shap_vals = shap_vals[:len(EXPECTED_FEATURES)]
            
        top_indices = np.argsort(np.abs(shap_vals))[-3:][::-1]
        top_features = [{"feature": EXPECTED_FEATURES[i], "impact": float(shap_vals[i])} for i in top_indices]
        
        # Get GeoIP for destination
        geo = await get_geoip(dst_ip)
        
        alert_payload = {
            "type": "alert",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "attack_prob": float(attack_prob),
            "geo": geo,
            "top_features": top_features,
            "protocol": record.get("Protocol", "TCP")
        }
        
        # Broadcast
        for connection in targets:
            try:
                await connection.send_json(alert_payload)
            except:
                pass

@app.on_event("startup")
async def startup_event():
    load_ml_components()
    asyncio.create_task(process_flow_stream())

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        # Send history so they see data immediately
        if redis_client:
            history = await redis_client.xrevrange(REDIS_STREAM, max='+', min='-', count=10)
            for msg_id, msg_data in reversed(history):
                record_str = msg_data.get(b"data")
                if record_str:
                    record = json.loads(record_str.decode('utf-8'))
                    await analyze_and_broadcast(record, [websocket])
                    
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api:app", host="0.0.0.0", port=8000, reload=True)
