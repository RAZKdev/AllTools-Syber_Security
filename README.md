# AllTools-CyberSec

> Practical defensive security workbench untuk asesmen, audit konfigurasi, dan pengujian keamanan defensif yang terotorisasi.

## 1. Deskripsi Proyek

**AllTools-CyberSec** adalah platform asesmen dan audit keamanan siber defensif untuk laboratorium lokal, pengujian sistem resmi yang memiliki izin (*authorized engagement*), dan audit kepatuhan konfigurasi. Aplikasi ini tidak berfokus pada alat serang destruktif, melainkan pada alur kerja **Evidence-First**: bukti → interpretasi → risiko → remediasi → laporan.

Setiap eksekusi modul wajib melewati **Scope Guard Engine** yang membatasi target pada aset yang diizinkan. Temuan disimpan bersama bukti, diberi sidik jari SHA-256, dan dapat diekspor menjadi laporan Markdown atau HTML.

## 2. Kenapa Proyek Ini Dibuat

Pengujian keamanan yang tidak terkendali dapat memindai aset di luar izin, menghasilkan false positive, atau menyajikan skor tanpa bukti yang dapat diaudit. Masalah ini berbahaya baik secara hukum maupun teknis.

AllTools-CyberSec dibuat untuk:

- **Mencegah scope creep:** target di luar izin diblokir sebelum paket jaringan dikirim.
- **Menjaga bukti:** setiap temuan didukung data mentah yang dapat diperiksa, dengan hash SHA-256 dan redaksi kredensial sensitif.
- **Memisahkan status:** `PASS`, `FAIL`, `WARN`, `ERROR`, `BLOCKED_OUT_OF_SCOPE`, dan `INSUFFICIENT_DATA` tidak dicampur menjadi satu skor.
- **Menyediakan antarmuka operasional:** dashboard, konsol eksekusi, inspector temuan, dan pratinjau laporan dalam satu workbench.
- **Mendukung audit yang dapat dipertanggungjawabkan:** laporan menjelaskan fakta, dampak, dan langkah remediasi.

## 3. Fungsi & Fitur Utama

1. **Scope Guard Engine** — validasi target berdasarkan domain, subdomain wildcard, alamat IP v4/v6, CIDR, dan URL prefix; blacklist/exclusion diprioritaskan di atas whitelist; mendukung masa berlaku izin.
2. **Modul Keamanan Defensif (11 aturan aktif):**
   - **Web:** audit header keamanan HTTP, flag cookie, kebocoran banner/teknologi, konfigurasi CORS, dan paparan file sensitif/`security.txt`.
   - **Transport & jaringan:** validasi sertifikat TLS, deteksi protokol usang, dan audit port/layanan yang terekspos.
   - **DNS:** audit SPF/DMARC dan rekaman CAA.
   - **Kriptografi & identitas:** analisis kekuatan algoritma hash dan audit kebijakan password/entropi.
3. **Evidence Store & Redaksi Otomatis** — hashing SHA-256, penyimpanan bukti, dan penyensoran pola seperti token, API key, password, private key, serta session cookie.
4. **Generator Laporan** — ekspor Markdown dan HTML siap cetak, berisi observasi, dampak, rekomendasi, dan tabel hash bukti.
5. **Workbench UI** — dashboard metrik, Scope Simulator, Executions Console, Findings Inspector, dan Reports View.
6. **Kontrak Domain Kanonik** — JSON Schema di `core/contracts/schemas/` sebagai sumber kebenaran model domain.

## 4. Bahasa Pemrograman & Teknologi

| Lapisan | Teknologi |
| --- | --- |
| Backend | Python 3.10+, FastAPI, Pydantic v2 |
| HTTP & testing | HTTPX, Pytest |
| Frontend | TypeScript, React 18, Vite 5 |
| UI | Lucide React, CSS variables/design tokens |
| Kontrak data | JSON Schema (Draft 2020-12) |

## 5. Struktur Direktori

```text
AllTools-Syber_Security/
├── backend/
│   ├── app/
│   │   ├── api/             # Endpoint scope, executions, findings, reports, evidence
│   │   ├── services/        # Scope Guard
│   │   ├── repositories/    # Repositori domain
│   │   └── schemas/         # Model Pydantic
│   └── tests/               # Pengujian API dan Scope Guard
├── core/contracts/          # JSON Schema dan tipe kontrak
├── frontend/                # React + TypeScript + Vite
├── security/                # Collector, rules, normalizer
├── evidence/                # Penyimpanan bukti dan redaksi
├── reports/                 # Generator laporan Markdown/HTML
├── tests/                   # Fixture dan pengujian rule
└── pytest.ini
```

## 6. Cara Menjalankan

**Prasyarat:** Python 3.10+ dan Node.js 18+.

### Backend

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r backend/requirements.txt
$env:PYTHONPATH=".;backend"
python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```

Swagger UI tersedia di `http://localhost:8000/docs`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Aplikasi tersedia di `http://localhost:5173`.

Repo ini **tidak** menyertakan `start.bat`; gunakan perintah manual di atas.

## 7. Pengujian

```bash
.venv\Scripts\pytest -v
```

Pengujian mencakup Scope Guard, API, dan aturan keamanan.

## 8. Batas Keamanan & Etika

Proyek ini hanya untuk pengujian defensif yang sah, audit konfigurasi, dan laboratorium riset lokal. Jangan gunakan untuk malware, pencurian kredensial, eksploitasi destruktif, persistensi tanpa izin, atau aktivitas ofensif ilegal. Pastikan Anda memiliki izin tertulis sebelum memindai sistem apa pun.

Belum ada berkas lisensi di repo. Hubungi pemilik repo untuk penggunaan ulang.
