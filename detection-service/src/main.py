import sys
import os
import json
import time
import argparse
import signal
import logging
from typing import List, Dict, Any

from model_loader import NIDSModelManager
from inference import NIDSInferenceEngine
from db_writer import NIDSDatabaseWriter

logger = logging.getLogger("nids.detection")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

running = True

def sig_handler(signum, frame):
    global running
    logger.info("[Detection Service] Shutdown signal received.")
    running = False
def process_stream(source="stdin", batch_size=100, flush_timeout=0.05, output_file=None, db_path=None, enable_db=True,
                   use_buffer=False, buffer_limit=500, buffer_interval=0.5):
    global running
    manager = NIDSModelManager()
    engine = NIDSInferenceEngine(manager)
    db_writer = NIDSDatabaseWriter(db_path) if (enable_db and db_path != "") else None

    logger.info("==========================================================")
    logger.info("   NIDS Real-time Detection Service (LightGBM Engine)    ")
    logger.info("==========================================================")
    logger.info(f"Source:           {'SQLite Buffer' if use_buffer else source}")
    logger.info(f"Model Classes:    {len(manager.id_to_label)} categories")
    logger.info(f"Features:         {len(manager.feature_names)} features")
    logger.info(f"Batch Size:       {batch_size}")
    if db_writer:
        logger.info(f"Database:         SQLite ({db_writer.db_path})")
    if use_buffer:
        logger.info(f"Buffer Limit:     {buffer_limit} flows per fetch")
        logger.info(f"Buffer Interval:  {buffer_interval}s")
    logger.info("Listening for flow records...")

    total_flows = 0
    malicious_flows = 0
    attack_counts: Dict[str, int] = {}
    batch_buffer: List[Dict[str, Any]] = []
    last_flush_time = time.time()

    out_fp = open(output_file, "a") if output_file else sys.stdout

    def flush_batch():
        nonlocal total_flows, malicious_flows, batch_buffer, last_flush_time
        if not batch_buffer:
            return
        
        t0 = time.time()
        results = engine.predict_batch(batch_buffer)
        dt_ms = (time.time() - t0) * 1000.0

        # Buffer IDs claimed by this batch. They are already in "processing"
        # state in the DB (see get_pending_raw_flows) and are only marked
        # "processed" after a successful insert.
        buffer_ids = [f.get("_buffer_id") for f in batch_buffer if f.get("_buffer_id")]

        insert_ok = True
        if db_writer:
            try:
                db_writer.insert_batch(results)
            except Exception as e:
                insert_ok = False
                logger.error(f"[Detection Service] Database insert error: {e}")

        for r in results:
            total_flows += 1
            det = r["detection"]
            if det["is_malicious"]:
                malicious_flows += 1
                atype = det["attack_type"]
                attack_counts[atype] = attack_counts.get(atype, 0) + 1

            # Output result
            line = json.dumps(r)
            out_fp.write(line + "\n")
            out_fp.flush()

        # Mark rows processed only after a successful insert. If the insert
        # failed, leave them claimed so the lease timeout can reclaim them
        # for retry instead of losing the detections.
        if db_writer and buffer_ids and insert_ok:
            try:
                db_writer.mark_raw_processed(buffer_ids)
            except Exception as e:
                logger.error(f"[Detection Service] Failed to mark buffer as processed: {e}")

        batch_buffer.clear()
        last_flush_time = time.time()

    try:
        if use_buffer and db_writer:
            # Buffer mode: poll the raw_flows table
            logger.info("Buffer mode: Polling SQLite for pending flows...")
            while running:
                # IMPORTANT: never fetch a new batch while the previous one is
                # still sitting unflushed in batch_buffer. The old code called
                # `continue` here as soon as a fetch returned rows, which
                # could re-enter get_pending_raw_flows() while a partial,
                # not-yet-flushed/not-yet-marked-processed remainder was still
                # in batch_buffer. If that remainder's rows were still
                # "pending" in the DB (because they hadn't been marked
                # processed yet), the next fetch could return the *same*
                # rows again, appending duplicates into batch_buffer and
                # feeding the same flow to the model more than once.
                # Fetching only happens now once batch_buffer is empty.
                if not batch_buffer:
                    raw_flows = db_writer.get_pending_raw_flows(limit=buffer_limit)
                else:
                    raw_flows = None

                if raw_flows:
                    for flow in raw_flows:
                        batch_buffer.append(flow)
                        if len(batch_buffer) >= batch_size:
                            flush_batch()
                    # Flush whatever remains below batch_size immediately
                    # instead of carrying it across the next fetch cycle.
                    if batch_buffer:
                        flush_batch()
                else:
                    if batch_buffer and (time.time() - last_flush_time >= flush_timeout):
                        flush_batch()
                    if not raw_flows:
                        time.sleep(buffer_interval)

        else:
            # Original stdin mode
            while running:
                line = sys.stdin.readline()
                if not line:
                    if len(batch_buffer) > 0:
                        flush_batch()
                    if not sys.stdin.isatty():
                        break
                    time.sleep(0.01)
                    continue

                line = line.strip()
                if not line or not line.startswith("{"):
                    continue

                try:
                    flow_obj = json.loads(line)
                    batch_buffer.append(flow_obj)
                except json.JSONDecodeError:
                    continue

                if len(batch_buffer) >= batch_size or (time.time() - last_flush_time >= flush_timeout):
                    flush_batch()

    finally:
        flush_batch()
        if output_file and out_fp != sys.stdout:
            out_fp.close()

    logger.info("\n--- Detection Session Summary ---")
    logger.info(f"Total Flows Processed: {total_flows:,}")
    logger.info(f"Benign Flows:          {(total_flows - malicious_flows):,}")
    logger.info(f"Malicious Detections:  {malicious_flows:,}")
    if attack_counts:
        logger.info("Attack Breakdown:")
        for atk, count in sorted(attack_counts.items(), key=lambda x: -x[1]):
            logger.info(f"  • {atk}: {count:,} ({count / total_flows * 100:.2f}%)")
    logger.info("[Detection Service] Terminated cleanly.")
def main():
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    parser = argparse.ArgumentParser(description="NIDS Detection Service with LightGBM")
    parser.add_argument("--source", choices=["stdin", "file"], default="stdin", help="Input stream source")
    parser.add_argument("--batch-size", type=int, default=50, help="Micro-batch size for LightGBM")
    parser.add_argument("--output", type=str, default=None, help="Output file for enriched alerts")
    parser.add_argument("--db-path", type=str, default=None, help="Custom SQLite database file path")
    parser.add_argument("--no-db", action="store_true", help="Disable database persistence")
    parser.add_argument("--buffer", action="store_true", help="Read from SQLite buffer table instead of stdin")
    parser.add_argument("--buffer-limit", type=int, default=500, help="Max flows to fetch per batch from buffer")
    parser.add_argument("--buffer-interval", type=float, default=0.5, help="Poll interval for buffer in seconds")
    args = parser.parse_args()

    process_stream(
        source=args.source,
        batch_size=args.batch_size,
        output_file=args.output,
        db_path=args.db_path,
        enable_db=(not args.no_db),
        use_buffer=args.buffer,
        buffer_limit=args.buffer_limit,
        buffer_interval=args.buffer_interval
    )

if __name__ == "__main__":
    main()
