# AllTools-CyberSec — Practical Defensive Security Workbench

[![Python Tests](https://img.shields.io/badge/Python%20Tests-26%20Passed-brightgreen)](#)
[![Vite Build](https://img.shields.io/badge/Vite%20Build-Passing-brightgreen)](#)
[![Security Policy](https://img.shields.io/badge/Security-Defensive%20Only-blue)](#)
[![Scope Guard](https://img.shields.io/badge/Scope%20Guard-Enforced%20(Default--Deny)-red)](#)

---

## 1. Identitas & Deskripsi Proyek

**AllTools-CyberSec** adalah *Practical Defensive Security Workbench* — sebuah platform asesmen dan audit keamanan siber defensif yang dirancang untuk laboratorium lokal, pengujian sistem resmi terotorisasi (*authorized engagement*), dan audit kepatuhan konfigurasi keamanan.

Aplikasi ini menolak pendekatan dramatis/alat serang destruktif (*theatrical hacking tools*), dan berfokus pada metodologi **Evidence-First** (Bukti → Interpretasi → Risiko → Remediasi → Laporan) dengan penegakan batasan cakupan yang ketat melalui **Scope Guard Engine**.

---

## 2. Alasan Mengapa Aplikasi Ini Dibuat

1. **Mencegah Pelanggaran Cakupan Target (*Scope Creep & Unauthorized Probing*)**:
   Banyak insiden keamanan terjadi saat pengujian sistem karena ketidaksengajaan memindai aset di luar izin resmi. AllTools-CyberSec mewajibkan seluruh modul melewati gerbang **Scope Guard** (*fail-closed default deny*), sehingga target di luar izin akan diblokir seketika sebelum paket jaringan dikirim.
2. **Kebutuhan Standar Bukti Forensik yang Transparan (*Evidence-First*)**:
   Mayoritas pemindai keamanan hanya menyajikan skor acak tanpa pembuktian yang jelas. Sistem ini menjamin setiap temuan (*Finding*) didukung oleh data mentah yang dapat diaudit, dilengkapi sidik jari kriptografis **SHA-256**, serta redaksi otomatis terhadap kredensial sensitif.
3. **Pemisahan Semantik Keamanan yang Akurat**:
   Kegagalan koneksi (*error*) atau kelonggaran konfigurasi (*warning*) sering disalahartikan sebagai kerentanan kritis (*false positive*). Workbench ini secara ketat membedakan status `PASS`, `FAIL`, `WARN`, `ERROR`, `BLOCKED_OUT_OF_SCOPE`, dan `INSUFFICIENT_DATA`.
4. **Antarmuka Khusus Operasional Defensif**:
   Menyediakan antarmuka kerja profesional bergaya *dark-first* tanpa ornamen hacker klise, memprioritaskan densitas informasi teknis yang rapi dan mudah dibaca oleh analis keamanan maupun pemangku kepentingan.

---

## 3. Bahasa Pemrograman & Arsitektur Teknologi

Sistem dibangun dengan arsitektur decoupled berorientasi kontrak kanonikal:

### Backend Application Layer
- **Bahasa Pemrograman:** Python 3.14+
- **Web Framework:** FastAPI (Asynchronous REST API)
- **Data Validation & Modeling:** Pydantic v2 (Pemetaan ketat terhadap kontrak JSON Schema)
- **Testing Framework:** Pytest (Unit tests, deterministik fixtures, integrasi API)
- **HTTP Engine:** HTTPX / Standard Socket & SSL

### Frontend Presentation Layer
- **Bahasa Pemrograman:** TypeScript (Strict Mode)
- **UI Framework & Tooling:** React 18 + Vite
- **Icons & Visuals:** Lucide React
- **Design System:** Native CSS Variables (Tokens System sesuai `DESIGN.md`)

### Shared Domain Contracts
- **Format:** JSON Schema (Draft 2020-12) di direktori `core/contracts/schemas/` sebagai satu-satunya *single source of truth* untuk seluruh domain model.

---

## 4. Fungsi & Fitur Utama

```text
Engagement → Scope Definition → Assessment → Checks → Observation → Finding → Evidence → Report
```

1. **Scope Guard Engine**:
   - Memvalidasi target berdasarkan Domain, Subdomain Wildcard (`*.example.local`), Alamat IP (v4/v6), CIDR Subnet (`10.0.0.0/16`), dan URL Prefix.
   - Kebijakan *blacklist/exclusion* (`inScope=false`) memiliki prioritas mutlak di atas *whitelist*.
   - Filter masa berlaku izin (*expiration date check*).
2. **Modular Security Engine**:
   - **`SEC-WEB-001` (HTTP Security Headers)**: Audit kepatuhan HSTS, CSP, X-Content-Type-Options: nosniff, X-Frame-Options: DENY, dan Referrer-Policy.
   - **`SEC-TLS-001` (TLS Certificate & Protocol)**: Audit kedaluwarsa sertifikat, kesesuaian hostname (CN/SAN), peringatan masa tenggang ($\le 14$ hari), dan pencegahan protokol usang (SSLv3, TLS 1.0, TLS 1.1).
   - **`SEC-DNS-001` (DNS Anti-Spoofing & Email Defense)**: Audit integritas rekaman SPF (`v=spf1`) dan kebijakan DMARC (`v=DMARC1`) pencegah pemalsuan domain email.
3. **Evidence Storage & Automated Redaction**:
   - Hashing SHA-256 untuk setiap bukti hasil observasi.
   - Sensor otomatis pola kredensial sensitif (`Bearer tokens`, `API keys`, `passwords`, `private keys`, `session cookies`).
4. **Sistem Pelaporan Audit Terstruktur**:
   - Ekspor laporan berstandar industri ke format **Markdown (`.md`)** dan **Printable HTML (`.html`)**.
   - Menyajikan fakta observasi, dampak teknis, rekomendasi langkah mitigasi, dan tabel hash bukti forensik.
5. **Interactive Workbench UI**:
   - **Dashboard**: Metrik eksekutif, status alur kerja, dan log eksekusi terbaru.
   - **Scope Simulator**: Pengujian izin target secara langsung sebelum eksekusi modul keamanan.
   - **Executions Console**: Eksekutor pemeriksaan terproteksi dengan audit trail durasi dan status.
   - **Findings Inspector**: Panel telaah temuan mendalam dengan filter tingkat keparahan (*Critical, High, Medium, Low*).
   - **Reports View**: Pratinjau laporan di browser dengan fitur unduh langsung.

---

## 5. Struktur Direktori

```text
alltools-cybersec/
├── backend/                   # Python + FastAPI application layer
│   ├── app/
│   │   ├── api/               # REST API endpoints (scope, executions, findings, reports)
│   │   ├── services/          # Scope Guard engine
│   │   ├── repositories/      # Repositori domain in-memory
│   │   └── schemas/           # Pydantic models (memetakan core/contracts)
│   └── tests/                 # Unit & integration tests backend
├── core/
│   └── contracts/             # Kontrak domain JSON Schema (Source of Truth)
├── frontend/                  # React + TypeScript + Vite UI
│   └── src/
│       ├── components/        # Badges, Layout, ScopeIndicator, EmptyState
│       ├── pages/             # Dashboard, Scope, Executions, Findings, Reports
│       └── services/          # API client
├── security/                  # Security engine (collectors, rules, normalizers)
├── evidence/                  # Abstraksi evidence store & redaksi data sensitif
├── reports/                   # Generator laporan Markdown & HTML
├── tests/                     # Fixtures deterministik & pengujian rule
└── pytest.ini                 # Konfigurasi pengujian Python
```

---

## 6. Panduan Menjalankan Sistem

### Prasyarat
- Python 3.10+ (Direkomendasikan Python 3.12 atau 3.14)
- Node.js v18+ dan npm

### 1. Menjalankan Backend
```powershell
# Masuk ke direktori backend dan aktifkan virtual environment
.\backend\.venv\Scripts\python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```
*API docs (Swagger UI) dapat diakses di:* `http://localhost:8000/docs`

### 2. Menjalankan Frontend
```powershell
cd frontend
npm run dev
```
*Aplikasi web dapat diakses di:* `http://localhost:5173`

### 3. Menjalankan Seluruh Automated Tests
```powershell
.\backend\.venv\Scripts\pytest -v
```

---

## 7. Batasan Keamanan & Etika Operasional (*Security Boundary*)

Proyek ini dibuat secara khusus untuk pengujian defensif berizin resmi (*authorized defensive security*), audit konfigurasi, dan laboratorium riset lokal. 

Dilarang keras menyalahgunakan kode ini untuk pembuatan malware, pencurian kredensial, eksploitasi destruktif, teknik evasif/siluman, persistensi tanpa izin, atau aktivitas ofensif ilegal lainnya.
