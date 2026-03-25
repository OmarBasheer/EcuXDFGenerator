# EcuXDFGenerator

A Flask web application that generates **TunerPro XDF v1.60** definition files from
ECU binary ROM images.  The primary target is **modern Hyundai / Kia Theta-II engines**
running a **Siemens SIM2k-250** ECU (HMC / KMC), although any supported ECU binary can
be processed.

---

## Prerequisites

| Requirement | Minimum version |
|-------------|----------------|
| Python | 3.9 |
| pip | 21 |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/OmarBasheer/EcuXDFGenerator.git
cd EcuXDFGenerator

# 2. (Recommended) Create and activate a virtual environment
python -m venv .venv
# Linux / macOS
source .venv/bin/activate
# Windows
.venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Running the application

```bash
python app.py
```

The server starts on **http://localhost:5000** by default.

To enable Flask's debug / auto-reload mode set the environment variable before
starting:

```bash
# Linux / macOS
FLASK_DEBUG=1 python app.py

# Windows (Command Prompt)
set FLASK_DEBUG=1 && python app.py

# Windows (PowerShell)
$env:FLASK_DEBUG="1"; python app.py
```

---

## Usage workflow

1. **Upload** – drag-and-drop or browse for your `.bin` ROM file (max 32 MB).
   For SIM2k-250 ECUs the binary is typically a **1 MB (1024 KB)** file.
2. **Analyze** – the tool scans the binary and detects regions, potential axes,
   calibration tables, checksum locations, and ASCII signatures.  The
   *Hyundai / Kia Theta-II SIM2k-250* profile is automatically suggested for
   1 MB Siemens binaries.
3. **Configure** – select an ECU profile, add or edit table definitions
   (scalar, 1-D curve, 2-D map, or bit flag), set math equations, and choose
   categories.
4. **Generate XDF** – download the finished `.xdf` file ready to open in
   [TunerPro RT](https://www.tunerpro.net/).
5. **Checksum Tool** (optional) – calculate and patch the checksum in the
   binary before reflashing.

---

## Supported ECU profiles

| Profile | Binary size | Endian | Checksum |
|---------|------------|--------|----------|
| Hyundai/Kia Theta-II SIM2k-250 *(primary)* | 1 MB | little | CRC-32 |
| Subaru EJ 1 MB (WRX / STI) | 1 MB | big | Denso/Subaru |
| Subaru EJ 512 KB | 512 KB | big | Denso/Subaru |
| Honda OBD1 256 KB | 256 KB | big | Honda |
| Honda OBD2 512 KB | 512 KB | big | Honda |
| Mitsubishi EVO 1 MB | 1 MB | little | CRC-32 |
| Generic 1 MB / 512 KB / 256 KB | various | big | SUM-32 / SUM-16 |

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | Main single-page application |
| `POST` | `/api/analyze` | Upload `.bin`, returns analysis JSON |
| `POST` | `/api/generate` | Receive XDF config JSON, download `.xdf` |
| `POST` | `/api/preview` | Receive XDF config JSON, return XML string |
| `POST` | `/api/checksum/calc` | Calculate checksums for uploaded binary |
| `POST` | `/api/checksum/patch` | Write corrected checksum, download patched `.bin` |
| `GET` | `/api/profiles` | Return ECU profile list |
