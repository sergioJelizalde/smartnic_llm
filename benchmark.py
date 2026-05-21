#!/usr/bin/env python3
"""
quick_benchmark.py - Minimal latency test for all-MiniLM-L6-v2
"""

import time
import glob
import sys
import torch
from sentence_transformers import SentenceTransformer

def quick_benchmark():
    # Load model
    print("Loading model...")
    start = time.time()
    
    device = sys.argv[1] if len(sys.argv) > 1 else "cpu"

    if device == "cuda" and not torch.cuda.is_available():
        raise RuntimeError("CUDA requested but PyTorch cannot see your GPU")

    print(f"Running on: {device}")

    model = SentenceTransformer(
        'sentence-transformers/all-MiniLM-L6-v2',
        device=device
    )

    load_time = (time.time() - start) * 1000
    print(f"Model loaded in {load_time:.2f} ms")
    
    # Find emails
    email_files = glob.glob("message_*.eml")
    if not email_files:
        print("No message_*.eml files found!")
        return
    
    print(f"\nTesting with {len(email_files)} emails...")
    
    # Read all emails
    emails = []
    for file in email_files[:10]:  # Test first 10
        with open(file, 'r', encoding='utf-8', errors='ignore') as f:
            emails.append(f.read())
    
    # Single encoding test
    print("\n--- Single Email Test ---")
    for i, email in enumerate(emails[:3]):
        start = time.time()
        embedding = model.encode([email])
        elapsed = (time.time() - start) * 1000
        print(f"Email {i+1}: {elapsed:.2f} ms, embedding dim: {embedding.shape}")
    
    # Batch encoding test
    print("\n--- Batch Encoding Test ---")
    batch_sizes = [1, 2, 4, 8, 16, 32]
    
    for batch_size in batch_sizes:
        if batch_size <= len(emails):
            batch = emails[:batch_size]
            start = time.time()
            embeddings = model.encode(batch)
            elapsed = (time.time() - start) * 1000
            print(f"Batch size {batch_size:2d}: {elapsed:.2f} ms total, "
                  f"{elapsed/batch_size:.2f} ms per email")

if __name__ == "__main__":
    quick_benchmark()
