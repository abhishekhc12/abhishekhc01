## Virus Scanning Web App (Python/Flask)

A simple file-scanning web app that calculates file hashes, optionally matches YARA rules, optionally runs ClamAV if installed, and can query VirusTotal if an API key is provided.

### Features
- Hashing: SHA-256, SHA-1, MD5
- File metadata display (size, MIME, extension)
- YARA scanning (if `yara-python` installed; sample rule included)
- Optional ClamAV scanning (if `clamscan` available on PATH)
- Optional VirusTotal lookup using `VIRUSTOTAL_API_KEY`

### Requirements
- Python 3.9+
- Windows supported (tested on Windows PowerShell)

### Setup
1. Create and activate a virtual environment:
   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
2. Install dependencies:
   ```powershell
   pip install -r requirements.txt
   ```
3. (Optional) Copy `.env.example` to `.env` and set `VIRUSTOTAL_API_KEY`.
4. Run the app:
   ```powershell
   python run.py
   ```
5. Open `http://127.0.0.1:5000` in your browser.

### Notes
- YARA: If you have issues installing `yara-python` on Windows, you can comment it out in `requirements.txt` and skip YARA scanning.
- ClamAV: Install ClamAV and ensure `clamscan` is on PATH if you want ClamAV scanning.

### Security
Uploaded files are stored temporarily and deleted after scanning. Do not expose this app publicly without additional hardening.


