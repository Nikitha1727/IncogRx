# IncogRx

Offline, CPU-only, LLM-free privacy firewall for Indian hospital records (English, Hindi and Hinglish).
Built for Yugaantar DevForge, Track 3: Secret Wards.

Status: Phase 0 (setup). The pipeline currently runs the official starter skeleton; detection, linking and the
privacy layer are being built.

## Run

```bash
pip install -r requirements.txt
RAKSHA_SECRET=<secret> python main.py --input <input dir> --output <empty output dir>
```

## Models

No LLMs, no generative models and no pretrained transformers are used.
