import os
import csv
import json
import time
import argparse
from kafka import KafkaProducer


def get_producer(bootstrap_servers=None):
    servers = bootstrap_servers or os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
    return KafkaProducer(
        bootstrap_servers=servers.split(','),
        value_serializer=lambda v: json.dumps(v).encode('utf-8')
    )


def stream_from_csv(csv_path: str, topic: str = "transactions", pause: float = 0.1, limit: int = None, bootstrap_servers: str = None):
    producer = get_producer(bootstrap_servers)
    print(f"[*] Streaming data from {csv_path} to topic '{topic}'...")

    with open(csv_path, mode='r', newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        count = 0
        for row in reader:
            tx = {}
            for k, v in row.items():
                k_clean = k.strip()
                if k_clean.upper().startswith("V") or k_clean in ("Amount", "Time", "Class"):
                    try:
                        tx[k_clean] = float(v)
                    except (ValueError, TypeError):
                        tx[k_clean] = v
                else:
                    tx[k_clean] = v

            tx["transaction_id"] = f"t_{count}"
            if "user_id" not in tx:
                tx["user_id"] = f"user_{count % 100}"

            producer.send(topic, tx)
            count += 1
            print(f" [->] Sent transaction {tx['transaction_id']} (Amount: {tx.get('Amount', 0.0)})")

            if limit and count >= limit:
                print(f"[*] Reached limit of {limit} transactions.")
                break

            time.sleep(pause)

    producer.flush()
    producer.close()
    print(f"[OK] Completed streaming {count} transactions.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stream credit card transactions to Kafka")
    parser.add_argument("--csv", default="data/creditcard.csv", help="Path to creditcard.csv")
    parser.add_argument("--topic", default="transactions", help="Kafka topic name")
    parser.add_argument("--pause", type=float, default=0.1, help="Delay between messages in seconds")
    parser.add_argument("--limit", type=int, default=500, help="Max records to stream")
    parser.add_argument("--bootstrap-servers", default=None, help="Kafka bootstrap servers")
    args = parser.parse_args()

    stream_from_csv(
        csv_path=args.csv,
        topic=args.topic,
        pause=args.pause,
        limit=args.limit,
        bootstrap_servers=args.bootstrap_servers
    )
