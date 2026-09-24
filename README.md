# AllTools-CyberSec — Practical Defensive Security Workbench

[![Python Tests](https://img.shields.io/badge/Python%20Tests-46%20Passed%20(100%25)-brightgreen)](#)
[![Vite Build](https://img.shields.io/badge/Vite%20Build-Passing-brightgreen)](#)
[![Security Policy](https://img.shields.io/badge/Security-Defensive%20Only-blue)](#)
[![Security Tools](https://img.shields.io/badge/Defensive%20Tools-11%20Active%20Modules-blueviolet)](#)
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

2. **Modular Defensive Security Engine (11 Tools / Rules Aktif)**:
   - **Web Application Security**:
     - **`SEC-WEB-001` (HTTP Security Headers Validation)**: Audit kepatuhan header defensif wajib: HSTS (`Strict-Transport-Security`), Content-Security-Policy (CSP), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy`, dan `Permissions-Policy`. (*CWE-693 / OWASP ASVS v4.0*).
     - **`SEC-WEB-002` (Cookie Defensive Flags Audit)**: Memvalidasi atribut keamanan pada `Set-Cookie` (`Secure`, `HttpOnly`, dan `SameSite=Strict|Lax`) untuk mencegah eksfiltrasi sesi pengguna melalui serangan XSS atau CSRF. (*CWE-1004, CWE-614 / OWASP Session Management*).
     - **`SEC-WEB-003` (Server Banner & Tech Stack Disclosure)**: Mendeteksi kebocoran informasi versi web server (`Server`), runtime platform (`X-Powered-By`), serta metadata framework yang dapat memudahkan pengintaian (*reconnaissance*) penyerang. (*CWE-200 / Information Exposure*).
     - **`SEC-WEB-004` (CORS Policy Misconfiguration Auditor)**: Mengidentifikasi konfigurasi Cross-Origin Resource Sharing berbahaya, seperti penggunaan wildcard origin (`*`) bersamaan dengan `Access-Control-Allow-Credentials: true` atau pemantulan origin liar tanpa validasi. (*CWE-942*).
     - **`SEC-WEB-005` (Sensitive Files Exposure & RFC 9116 security.txt)**: Memverifikasi keberadaan kontak pelaporan kerentanan standar `/.well-known/security.txt` serta menguji potensi keterpaparan file sensitif publik seperti repositori git (`.git/HEAD`) dan variabel environment (`.env`). (*CWE-552*).
   - **Transport & Network Security**:
     - **`SEC-TLS-001` (TLS Certificate & Deprecated Protocol Check)**: Audit validitas sertifikat X.509, kesesuaian Subject Alternative Names (SAN), peringatan dini masa kedaluwarsa ($\le 14$ hari), dan deteksi protokol kriptografi usang (SSLv3, TLS 1.0, TLS 1.1). (*CWE-295, CWE-326*).
     - **`SEC-NET-001` (Authorized TCP Port & Service Exposure Probe)**: Mengaudit keterpaparan port jaringan kritis (Database, SSH, Telnet, RDP, SMB, Redis) terhadap daftar port resmi terotorisasi guna mencegah tereksposnya interface manajemen ke publik. (*CWE-668 / CIS Benchmarks*).
   - **DNS & Domain Security**:
     - **`SEC-DNS-001` (DNS Anti-Spoofing & Email Defense)**: Audit integritas rekaman SPF (`v=spf1`) dan DMARC (`v=DMARC1`) dengan deteksi kelonggaran kebijakan `p=none` pencegah serangan pemalsuan email (Business Email Compromise/Phishing). (*CWE-358*).
     - **`SEC-DNS-002` (DNS CAA Record Pinning Check)**: Memvalidasi rekaman DNS Certification Authority Authorization (RFC 8659) untuk membatasi CA mana saja yang berhak menerbitkan sertifikat SSL/TLS atas nama domain. (*CWE-295*).
   - **Cryptography & Identity**:
     - **`SEC-CRYPTO-001` (Cryptographic Hash Algorithm Strength Analyzer)**: Menganalisis algoritma hash terhadap risiko serangan tabrakan (*collision*) pada fungsi hash usang (MD5, SHA-1) serta merekomendasikan standar modern (SHA-256, SHA-512, Argon2, bcrypt). (*CWE-327, CWE-328*).
     - **`SEC-AUTH-001` (Password Policy & Shannon Entropy Auditor)**: Menghitung skor entropi Shannon informasi (bits per karakter), panjang sandi, keragaman karakter, serta pengecekan daftar kata sandi umum sesuai panduan NIST SP 800-63B. (*CWE-521*).

3. **Evidence Storage & Automated Redaction**:
   - Hashing SHA-256 untuk setiap bukti hasil observasi.
   - Sensor otomatis pola kredensial sensitif (`Bearer tokens`, `API keys`, `passwords`, `private keys`, `session cookies`).
4. **Sistem Pelaporan Audit Terstruktur**:
   - Ekspor laporan berstandar industri ke format **Markdown (`.md`)** dan **Printable HTML (`.html`)**.
   - Menyajikan fakta observasi, dampak teknis, rekomendasi langkah mitigasi, dan tabel hash bukti forensik.
5. **Interactive Workbench UI**:
   - **Dashboard**: Metrik eksekutif, katalog interaktif 11 modul keamanan defensif, status alur kerja, dan log eksekusi terbaru.
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

### Cara Cepat (1-Click Unified Launcher)
Cukup klik ganda (double-click) file **`start.bat`** di direktori utama:
- Otomatis memvalidasi dependensi Python dan Node.js/NPM
- Otomatis menyiapkan environment backend dan frontend bila belum terpasang
- Menjalankan Backend (port 8000) dan Frontend (port 5173) secara terpadu
- Langsung membuka AllTools-CyberSec di browser default (`http://127.0.0.1:5173`)
- **Cara Mematikan Server**: Cukup **tutup jendela/tab CMD tersebut** (klik tombol `X`) atau tekan `Ctrl+C`. Seluruh proses server akan otomatis dimatikan secara bersih dan port langsung dibebaskan.

---

### Cara Manual

#### 1. Menjalankan Backend
```powershell
$env:PYTHONPATH=".;backend"
.\backend\.venv\Scripts\python -m uvicorn app.main:app --app-dir backend --reload --port 8000
```
*API docs (Swagger UI) dapat diakses di:* `http://localhost:8000/docs`

#### 2. Menjalankan Frontend
```powershell
cd frontend
npm run dev
```
*Aplikasi web dapat diakses di:* `http://localhost:5173`

#### 3. Menjalankan Seluruh Automated Tests
```powershell
.\backend\.venv\Scripts\pytest -v
```

---

## 7. Batasan Keamanan & Etika Operasional (*Security Boundary*)

Proyek ini dibuat secara khusus untuk pengujian defensif berizin resmi (*authorized defensive security*), audit konfigurasi, dan laboratorium riset lokal. 

Dilarang keras menyalahgunakan kode ini untuk pembuatan malware, pencurian kredensial, eksploitasi destruktif, teknik evasif/siluman, persistensi tanpa izin, atau aktivitas ofensif ilegal lainnya.
