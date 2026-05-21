import glob
import sys
import time
import torch
from sentence_transformers import SentenceTransformer


DEVICE = sys.argv[1] if len(sys.argv) > 1 else "cpu"

if DEVICE == "cuda" and not torch.cuda.is_available():
    raise RuntimeError("CUDA requested, but PyTorch cannot see your GPU.")

print(f"\nRunning on: {DEVICE}")
if DEVICE == "cuda":
    print(f"GPU: {torch.cuda.get_device_name(0)}")


MODELS = {
    "MiniLM": "sentence-transformers/all-MiniLM-L6-v2",
    "DistilBERT": "sentence-transformers/distilbert-base-nli-stsb-mean-tokens",
}


def load_emails():
    files = sorted(glob.glob("message_*.eml"))

    if not files:
        raise FileNotFoundError("No message_*.eml files found.")

    emails = []
    for filename in files:
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            emails.append(f.read())

    return files, emails


def benchmark_model(model_name, model_id, emails):
    print(f"\n=== {model_name} ===")
    print(f"Model: {model_id}")

    model = SentenceTransformer(model_id, device=DEVICE)

    # Warmup avoids counting first-run overhead
    _ = model.encode(
        emails[0],
        convert_to_tensor=True,
        device=DEVICE,
        show_progress_bar=False,
    )

    if DEVICE == "cuda":
        torch.cuda.synchronize()
        torch.cuda.reset_peak_memory_stats()

    per_email_times = []
    embeddings = []

    total_start = time.perf_counter()

    for i, email in enumerate(emails, start=1):
        start = time.perf_counter()

        embedding = model.encode(
            email,
            convert_to_tensor=True,
            device=DEVICE,
            show_progress_bar=False,
        )

        if DEVICE == "cuda":
            torch.cuda.synchronize()

        elapsed = time.perf_counter() - start
        per_email_times.append(elapsed)
        embeddings.append(embedding)

        print(f"Email {i:03d}: {elapsed * 1000:.3f} ms")

    total_time = time.perf_counter() - total_start

    avg_ms = sum(per_email_times) / len(per_email_times) * 1000
    min_ms = min(per_email_times) * 1000
    max_ms = max(per_email_times) * 1000
    throughput = len(emails) / total_time

    print("\nBudget summary:")
    print(f"Emails processed:      {len(emails)}")
    print(f"Total encode time:     {total_time:.4f} sec")
    print(f"Average per email:     {avg_ms:.3f} ms")
    print(f"Minimum per email:     {min_ms:.3f} ms")
    print(f"Maximum per email:     {max_ms:.3f} ms")
    print(f"Throughput:            {throughput:.2f} emails/sec")
    print(f"Embedding dimension:   {embeddings[0].shape[-1]}")

    if DEVICE == "cuda":
        memory_mb = torch.cuda.max_memory_allocated() / 1024 / 1024
        print(f"Max GPU memory:        {memory_mb:.2f} MB")

    return {
        "model": model_name,
        "emails": len(emails),
        "total_sec": total_time,
        "avg_ms": avg_ms,
        "min_ms": min_ms,
        "max_ms": max_ms,
        "throughput": throughput,
        "embedding_dim": embeddings[0].shape[-1],
    }


def main():
    files, emails = load_emails()

    print(f"Found {len(files)} email file(s).")

    results = []

    for model_name, model_id in MODELS.items():
        result = benchmark_model(model_name, model_id, emails)
        results.append(result)

    print("\n=== Final Per-Email Budget Comparison ===")
    print(
        f"{'Model':<12} "
        f"{'Emails':>8} "
        f"{'Avg ms/email':>14} "
        f"{'Min ms':>10} "
        f"{'Max ms':>10} "
        f"{'Emails/sec':>12} "
        f"{'Dim':>8}"
    )
    print("-" * 82)

    for r in results:
        print(
            f"{r['model']:<12} "
            f"{r['emails']:>8} "
            f"{r['avg_ms']:>14.3f} "
            f"{r['min_ms']:>10.3f} "
            f"{r['max_ms']:>10.3f} "
            f"{r['throughput']:>12.2f} "
            f"{r['embedding_dim']:>8}"
        )


if __name__ == "__main__":
    main()