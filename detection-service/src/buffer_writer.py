#!/usr/bin/env python3
"""
Buffer Writer - Receives JSON flows from stdin and writes them to SQLite WAL buffer table.
This acts as a persistent, crash-safe queue between flow-capture and main.py.
"""
import sys
import os
import json
import time
import signal
import logging
from typing import List
import argparse

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from db_writer import NIDSDatabaseWriter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("nids.buffer_writer")

running = True
BATCH_SIZE = 100
FLUSH_TIMEOUT = 0.5  # seconds

def signal_handler(sig, frame):
    global running
    logger.info("Shutdown signal received, flushing remaining buffer...")
    running = False

def main():
    global running
    parser = argparse.ArgumentParser()
    parser.add_argument("--db-path", type=str, default=None,
                        help="Custom SQLite database file path")
    parser.add_argument("--interface", type=str, default=None,
                        help="Network interface name to store with each flow")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    db_writer = NIDSDatabaseWriter(args.db_path)
    db_writer.init_database()    
    logger.info("=" * 60)
    logger.info("  NIDS Buffer Writer (SQLite WAL Queue)")
    logger.info("=" * 60)
    logger.info(f"Database: {db_writer.db_path}")
    logger.info(f"Interface: {args.interface}")        
    logger.info(f"Batch Size: {BATCH_SIZE}")
    logger.info(f"Flush Timeout: {FLUSH_TIMEOUT}s")
    logger.info("Listening for JSON flows on stdin...")

    batch: List[str] = []
    last_flush = time.time()
    total_written = 0

    try:
        while running:
            line = sys.stdin.readline()
            if not line:
                if batch:
                    # Flush remaining on EOF
                    db_writer.write_raw_batch(batch)
                    total_written += len(batch)
                    logger.info(f"Flushed {len(batch)} flows on EOF (total: {total_written})")
                    batch.clear()
                if not sys.stdin.isatty():
                    # stdin closed, exit cleanly
                    break
                time.sleep(0.01)
                continue

            line = line.strip()
            if not line or not line.startswith("{"):
                continue

            # Inject the capture interface into each flow so the dashboard
            # can display it. Preserve net_interface as a compatibility alias.
            try:
                flow_obj = json.loads(line)
                if args.interface:
                    flow_obj["interface"] = args.interface
                    if "net_interface" not in flow_obj:
                        flow_obj["net_interface"] = args.interface
                modified_line = json.dumps(flow_obj)
                batch.append(modified_line)
            except json.JSONDecodeError:
                logger.warning(f"Skipping invalid JSON: {line[:100]}...")
                continue

            # Flush if batch full or timeout
            if len(batch) >= BATCH_SIZE or (time.time() - last_flush) >= FLUSH_TIMEOUT:
                if batch:
                    db_writer.write_raw_batch(batch)
                    total_written += len(batch)
                    logger.debug(f"Flushed {len(batch)} flows (total: {total_written})")
                    batch.clear()
                last_flush = time.time()

    finally:
        # Final flush
        if batch:
            db_writer.write_raw_batch(batch)
            total_written += len(batch)
            logger.info(f"Final flush: {len(batch)} flows (total: {total_written})")

    logger.info(f"Buffer Writer stopped. Total flows written: {total_written}")

if __name__ == "__main__":
    main()