import asyncio

# Monkey patch for Python 3.14+ where set_child_watcher and get_child_watcher were removed
if not hasattr(asyncio, 'set_child_watcher'):
    asyncio.set_child_watcher = lambda watcher: None
    class DummyWatcher:
        def __init__(self): pass
        def attach_loop(self, loop): pass
        def add_child_handler(self, pid, callback, *args): pass
        def remove_child_handler(self, pid): pass
        def close(self): pass
        def is_active(self): return False
    dummy_watcher_instance = DummyWatcher()
    asyncio.SafeChildWatcher = DummyWatcher
    asyncio.get_child_watcher = lambda: dummy_watcher_instance

# Create and set a global event loop for pyshark to use internally
loop = asyncio.new_event_loop()
asyncio.set_event_loop(loop)

import json
import logging
from typing import List

import pyshark
import redis
from pcap_feature_extractor import PCAPFeatureExtractor

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("live_sniffer")

# Configuration
INTERFACE = "en0"  # Adjust if the active interface is different (e.g., eth0, wlan0)
REDIS_URL = "redis://localhost:6379"
BATCH_SIZE = 50  # Packets to accumulate before processing
REDIS_STREAM = "live_network_flows"

def sniff_and_stream():
    """Captures live traffic, extracts features, and streams to Redis synchronously."""
    
    logger.info(f"Connecting to Redis at {REDIS_URL}...")
    try:
        r = redis.from_url(REDIS_URL)
        r.ping()
        logger.info("Connected to Redis successfully.")
    except Exception as e:
        logger.error(f"Failed to connect to Redis: {e}")
        return

    extractor = PCAPFeatureExtractor(flow_timeout=30.0)  # Reduced timeout for faster real-time streaming
    
    logger.info(f"Starting live capture on interface: {INTERFACE}")
    capture = pyshark.LiveCapture(interface=INTERFACE)
    
    packet_batch = []
    
    try:
        for packet in capture.sniff_continuously():
            packet_batch.append(packet)
            
            if len(packet_batch) >= BATCH_SIZE:
                # Extract features
                try:
                    features_df = extractor.extract_features_from_batch(packet_batch)
                    
                    if not features_df.empty:
                        # Convert DataFrame records to dicts for Redis
                        records = features_df.to_dict(orient="records")
                        for record in records:
                            # Add a timestamp to the record for downstream processing
                            record_str = json.dumps(record, default=str)
                            r.xadd(REDIS_STREAM, {"data": record_str})
                        
                        logger.info(f"Pushed {len(records)} completed flows to Redis stream '{REDIS_STREAM}'")
                except Exception as e:
                    logger.error(f"Error extracting/pushing features: {e}")
                
                # Reset batch
                packet_batch = []
    except KeyboardInterrupt:
        logger.info("Stopping live sniffer...")

if __name__ == "__main__":
    sniff_and_stream()
