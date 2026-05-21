# smartnic_llm: SentenceTransformers CPU/GPU Benchmark

This repository runs a Python benchmark for comparing SentenceTransformer embedding performance on CPU and GPU/CUDA.

## Requirements

- Anaconda or Miniconda
- Python 3.11
- Internet connection for downloading models
- Email input files named `message_*.eml`
- Optional: NVIDIA GPU for CUDA runs

## Build DPDK SMTP Extractor

```bash
make
```

This builds the DPDK SMTP extractor and creates the executable:

```bash
./build/smtp_extract
```

## Run DPDK SMTP Extractor

```bash
sudo ./build/smtp_extract -l 0 -n 4 -- -p 0x1
```

Arguments:

```text
-l 0      use logical core 0
-n 4      use 4 memory channels
--        separates DPDK EAL arguments from application arguments
-p 0x1    application port mask, use port 0
```

After the extractor writes `message_*.eml` files, run the benchmark.

## Create Environment

```powershell
conda create -n llm_env python=3.11 -y
conda activate llm_env
python -m pip install --upgrade pip
```

## Install SentenceTransformers

```powershell
python -m pip install -U sentence-transformers
```

## Optional CUDA PyTorch Install

Use this only if you want GPU/CUDA support.

```powershell
python -m pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu128
```

## Verify Installation

```powershell
where python
python --version
python -m pip --version
python -c "import sentence_transformers; print(sentence_transformers.__version__)"
```

## Verify CUDA

```powershell
python -c "import torch; print('Torch:', torch.__version__); print('CUDA available:', torch.cuda.is_available()); print('Device:', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU only')"
```

## Input Files

Place email files in the same folder as `benchmark.py`.

Example:

```text
smartnic_llm/
  benchmark.py
  message_1.eml
  message_2.eml
  message_3.eml
```

Basic install:

```powershell
conda create -n llm_env python=3.11 -y
conda activate llm_env
python -m pip install --upgrade pip
python -m pip install -U sentence-transformers
```

Run CPU:

```powershell
python .\benchmark.py cpu
```

Run GPU:

```powershell
python .\benchmark.py cuda
```
