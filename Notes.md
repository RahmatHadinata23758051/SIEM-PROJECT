# Hybrid SIEM Notes

## Fokus Phase 1
- Stabilkan data pipeline sebelum masuk ke AI.
- Sumber log utama: `/var/log/auth.log` dari `sshd`.
- Unit data utama: agregasi per `ip` dalam window 60 detik.

## Backlog
1. Definisikan event schema SSH yang konsisten untuk parser.
2. Parse `auth.log` menjadi structured event.
3. Tentukan event canonical yang dihitung sebagai auth attempt agar tidak double count.
4. Implement feature extraction per IP per time window.
5. Generate dataset CSV untuk training dan evaluasi.
6. Tambahkan rule-based detector sederhana untuk brute force.
7. Integrasikan risk scoring 0-100.
8. Tambahkan watchlist, strike, dan decay mechanism.
9. Masuk ke Isolation Forest setelah pipeline data stabil.

## Keputusan Teknis Saat Ini
- Parser hanya fokus pada event `sshd` yang relevan.
- Event `failed_password`, `invalid_user`, `pam_auth_failure`, dan `accepted_auth` sekarang diperlakukan sebagai auth signal.
- Canonical auth attempt dibentuk lewat dedup pendek berbasis `ip`, `port`, `session_id`, dan waktu agar signal tetap kaya tanpa double count.
- Window default feature extraction adalah 60 detik.
- Jika dalam satu window hanya ada satu attempt, `inter_arrival_avg` disimpan sebagai `None`.
- Feature tambahan `event_count` dipakai untuk menangkap jumlah raw auth signal dalam satu window setelah canonical attempt dibentuk.

## Sudah Dikerjakan
- Struktur package Python awal dibuat.
- Parser `auth.log` dibuat dengan event schema yang reusable.
- Feature extraction per IP per window dibuat.
- Generator dataset CSV dan CLI end-to-end dibuat.
- Sample log dan test dasar parser + feature extraction ditambahkan.
- Generator synthetic corpus besar untuk traffic legal + ilegal acak berbasis profil perilaku ditambahkan.
- CLI untuk membangun `auth.log` sintetis dan CSV feature ukuran target ditambahkan.
- Corpus sintetis besar berhasil dibuat: `100000` row CSV, `483760` parsed event, `335` username unik, file CSV `5.23 MB`.
- Profil generator kini dipisah menjadi `mixed` dan `honeypot` agar bisa mengikuti referensi SSH illegal login dataset.
- Corpus `honeypot` berhasil dibuat: `99827` row CSV, `1918281` parsed event, file CSV `5.31 MB`, dominan failed login.
- Refactor canonical attempt normalization dan deduplication sudah selesai.
- Rule-based detector, risk scoring engine, watchlist state, decision engine, dan dataset validation module sudah ditambahkan.
- End-to-end test untuk typo login, slow attack, dan distributed attack sudah ditambahkan.
- Modul kalibrasi threshold berbasis distribusi dataset sudah ditambahkan.
- Modul evaluasi skenario, plot, trace CSV, dan report generator sudah ditambahkan.
- Evaluasi corpus `mixed` vs `honeypot` sudah dijalankan untuk mengkalibrasi threshold rule.

## Ringkasan Implementasi Saat Ini
- Package utama `hybrid_siem` sudah berisi parser, canonical attempt normalizer, feature extractor, dataset builder, synthetic dataset generator, validator, rule detector, risk scorer, watchlist, decision engine, dan processing pipeline.
- Package utama sekarang juga berisi modul kalibrasi threshold, analisis distribusi feature, evaluasi korelasi, evaluator skenario, dan CLI evaluasi.
- Parser SSH sudah mendukung event `failed_password`, `accepted_auth`, `invalid_user`, `pam_auth_failure`, `preauth_disconnect`, dan `client_disconnect`.
- Feature wajib Phase 1 sudah dihasilkan per IP per 60 detik: `failed_count`, `request_rate`, `username_variance`, `inter_arrival_avg`, `failed_ratio`, dan `event_count`.
- CLI dataset builder tersedia untuk mengubah `auth.log` menjadi CSV feature.
- CLI synthetic generator tersedia untuk membuat corpus `mixed` dan `honeypot`.
- CLI validator tersedia untuk membaca CSV feature dan mencetak ringkasan distribusi.
- CLI evaluator tersedia untuk menjalankan analisis distribusi, kalibrasi threshold, skenario validation, dan output plot/report ke folder hasil.

## Artefak Yang Sudah Dibuat
- Sample parser input: `data/samples/auth.log`.
- Sample CSV kecil hasil pipeline: `data/generated/ssh_features.csv`.
- Corpus synthetic `mixed`: `data/generated/synthetic_auth.log` dan `data/generated/synthetic_ssh_features.csv`.
- Corpus synthetic `honeypot`: `data/generated/synthetic_honeypot_auth.log` dan `data/generated/synthetic_honeypot_features.csv`.
- Artefak evaluasi terbaru ditulis ke `data/generated/evaluation/` berupa report teks, threshold JSON, summary JSON, trace CSV, dan plot PNG.
- File generated test juga sudah sempat dibuat untuk validasi lokal di `data/generated/`.

## Verifikasi Yang Sudah Dilakukan
- Unit test parser dan feature extraction sudah dibuat.
- Unit test synthetic generator untuk profile `mixed` dan `honeypot` sudah dibuat.
- Unit test detection pipeline dan validation module sudah dibuat.
- Unit test kalibrasi threshold dan evaluation bundle sudah dibuat.
- Verifikasi lokal terakhir: `python -m unittest discover -s tests -v` lulus.
- Verifikasi generation corpus besar berhasil untuk target CSV sekitar `5 MB` pada dua profile synthetic.
- Evaluasi CLI berhasil dijalankan terhadap corpus `mixed` sebagai baseline normal-like dan corpus `honeypot` sebagai attack-like.

## Hasil Kalibrasi Saat Ini
- Dataset baseline normal-like untuk kalibrasi diambil dari subset `likely_normal_subset` agar threshold tidak ikut terseret oleh row attack yang ada di corpus `mixed`.
- Threshold hasil kalibrasi saat ini:
  - `failed_count`: low `2`, medium `4`, high `8`
  - `request_rate`: low `0.04`, medium `0.08`, high `0.16`
  - `username_variance`: low `2`, medium `4`, high `8`
  - `failed_ratio`: low `0.60`, medium `0.80`, high `0.92`
  - `event_count`: low `3`, medium `6`, high `12`
  - `inter_arrival_fast`: low `12.0`, medium `6.0`, high `3.0`
  - `slow_attack` pattern: failed_count `2`, failed_ratio `0.80`, request_rate_max `0.05`, inter_arrival_min `20.0`

## Temuan Evaluasi Saat Ini
- `normal_typo` tetap `normal` dan tidak pernah terblokir.
- `slow_bruteforce` naik bertahap sampai `rate_limit`, lalu turun lagi ke `monitor` setelah window tenang.
- `aggressive_bruteforce` langsung spike ke `block`, lalu decay ke `rate_limit` setelah gap 12 menit sesuai aturan decay high `-2/menit`.
- `distributed_attack` menunjukkan kenaikan risk bertahap per IP sampai `rate_limit`.
- Korelasi menunjukkan `failed_count`, `request_rate`, dan `event_count` sangat redundant pada window 60 detik tetap, jadi nanti perlu dipertimbangkan saat masuk ke model AI.

## Status Git
- Source code awal sudah di-commit dan di-push ke branch `main`.
- Artefak besar di `data/generated/` dan cache Python tidak dimasukkan ke git melalui `.gitignore`.

## Perubahan Terbaru (Update Terakhir)
- **Modul Anomaly Detection dengan Isolation Forest**: File baru `hybrid_siem/anomaly.py` ditambahkan dengan implementasi lengkap:
  - `IsolationForestConfig`: Dataclass untuk konfigurasi model dengan parameter default:
    - Feature default: `failed_count`, `username_variance`, `inter_arrival_avg`, `failed_ratio`
    - Scaler: Standard scaler, contamination: 0.03, n_estimators: 200
    - Smoothing score dengan exponential moving average (EMA) dengan alpha: 0.35
  - `fit_isolation_forest()`: Function untuk training model dari feature record dengan strategi seleksi data
  - `AnomalyTrainingReport`: Dataclass untuk menyimpan metadata training
  - Support untuk normalisasi feature menggunakan quantile-based scaling (0.75-0.995)
  - Smoothing anomaly score dengan moving average untuk mereduksi noise

- **Integrasi Anomaly Score di Pipeline Decision**:
  - `PipelineDecision` di `hybrid_siem/pipeline.py` sekarang memiliki field `raw_anomaly_score` dan `anomaly_score`
  - Risk scoring sekarang menggabungkan rule-based score + anomaly score dengan weights yang dapat dikonfigurasi
  - `RiskWeights` di `hybrid_siem/risk.py` ditambahkan untuk mengontrol bobot rule vs anomaly

- **Update Modul Evaluasi dan Scenario**:
  - `hybrid_siem/evaluation.py` sekarang mengintegrasikan anomaly training dan scoring:
    - `EvaluationArtifacts` memiliki `anomaly_model_path` untuk menyimpan model pickle
    - `EvaluationSummary` memiliki `anomaly_training` report dan anomaly score di output trace
  - Plot scenario sekarang menampilkan 3 subplot: risk score, anomaly score, dan perbandingan rule vs AI score
  - Trace CSV sekarang menyertakan kolom `raw_anomaly_score` dan `anomaly_score` untuk analisis detail

- **New Test Module**: `tests/test_anomaly_integration.py` ditambahkan untuk unit testing anomaly detection

- **Update CLI dan Utilities**:
  - `hybrid_siem/__init__.py` di-update untuk export anomaly-related classes
  - `hybrid_siem/evaluate_cli.py` di-update untuk mendukung anomaly model training
  - `hybrid_siem/scenarios.py` ditambahkan scenario definition untuk testing anomaly
  - Test module `tests/test_calibration_evaluation.py` di-update untuk test anomaly integration

**Ringkasan Status Implementasi Saat Ini:**
- Phase 1 rule-based detection + watchlist sudah stabil
- Phase 2 unsupervised anomaly detection (Isolation Forest) sudah diintegrasikan end-to-end
- Evaluasi pipeline kini mendukung kombinasi rule-based + anomaly score dengan risk aggregation
- Model dapat disimpan dan di-load kembali dari disk
- Trace dan plot scenario sekarang menampilkan kontribusi AI (anomaly) vs rule-based detection

## Phase 3: Adversarial Robustness dan Advanced Risk Modeling (BARU)

### ✅ TASK 1 — Non-linear Risk Scoring (SELESAI)
Sistem risk scoring sekarang mendukung multiple strategi untuk handling kombinasi rule dan anomaly score yang lebih sophisticated:

- **Linear Scoring** (default): `risk = rule_weight * rule + anomaly_weight * anomaly`
- **Adaptive Weighting**: Boosts salah satu signal jika yang lain lemah
  - Jika rule_score < 50 tapi anomaly_score >= 0.5 → anomaly weight naik ke 1.5x
  - Jika anomaly_score < 0.5 tapi rule_score >= 50 → rule weight naik ke 1.5x
- **Conditional Boosting**: Jika rule >= 70 AND anomaly >= 0.7 → tambah +20 poin risk score
- **Sigmoid Transformation** (optional): Smooth non-linear blending untuk hasil yang lebih gradual

Implementasi: `hybrid_siem/risk.py` dengan `RiskWeights` config yang dapat dikustomisasi

### ✅ TASK 2 — Adversarial Attack Simulation (SELESAI)
Ditambahkan 4 scenario adversarial untuk testing robustness sistem:

1. **low_and_slow_distributed** (192.0.2.0/24): 10 IP berbeda, masing-masing 1 failure per 3-4 menit
   - Target: Test apakah sistem mendeteksi distributed attack yang lambat
   - Expected: Tetap di status `monitor` (per-IP risk rendah, tapi pattern terdeteksi)

2. **username_reuse_attack** (203.0.113.10): Hanya 2 username (admin/root) dicoba berulang 16x dalam 2 menit
   - Target: Test credential stuffing dengan low variance
   - Expected: `rate_limit` (persistent attempt pada username terbatas)

3. **human_like_attack** (198.51.100.99): Mix success dan failure dengan random delay
   - Target: Test apakah attack dengan pattern "manusia" terdeteksi
   - Expected: `rate_limit` (fakta ada failures di sela-sela successes)

4. **mimic_normal_traffic** (203.0.113.15): Legitimate activity dicampur failed login attempts
   - Target: Test apakah system bisa membedakan normal dari attack yang menyamar
   - Expected: `monitor` → `normal` (failed ratio rendah karena tercampur successes)

### ✅ TASK 3 — Temporal Feature Extension (SELESAI)
Ditambahkan modul baru `hybrid_siem/temporal.py` untuk capturing pattern temporal yang tidak terlihat dalam satu window:

- **rolling_failed_count_5m**: Jumlah failures dalam 5 window terakhir (300 detik)
- **rolling_request_rate_5m**: Rata-rata request rate dalam 5 window terakhir
- **persistence_score**: Berapa lama IP sudah terobservasi (0-100 scale, max 8 jam)
- **burst_score**: Deteksi sudden spike dalam failed attempts vs rolling average
- **activity_duration_seconds**: Total durasi aktivitas sejak first observation
- **quiet_period_seconds**: Gap waktu sejak window sebelumnya

Implementasi: `TemporalFeatureComputer` yang mengagregasi feature records per IP

### ✅ TASK 4 — Adaptive Watchlist Enhancement (SELESAI)
Enhanced `hybrid_siem/watchlist.py` dengan history tracking dan sensitivity adjustment:

- **historical_peak**: Highest risk score pernah mencapai berapa untuk IP ini
- **repeat_incidents**: Berapa kali IP masuk recovery kemudian spike lagi
- **adaptive_sensitivity**: Multiplier (1.0-3.0x) yang meningkat dengan strike count dan repeat incidents
  - IP dengan 3+ strikes atau 2+ repeat incidents → sensitivity up to 3.0x
  - Observed risk score dikali dengan adaptive_sensitivity sebelum aggregation
  - Contoh: IP dengan bad history + risk 50 → menjadi 50 * 2.0 = 100 (automatically escalated)

Implementasi: Enhanced scoring logic dalam `update()` method untuk adaptive risk boost

### ✅ TASK 5 — Explainability (SELESAI)
Enhanced `hybrid_siem/pipeline.py` dengan detailed reasoning untuk setiap decision:

- **_build_explanations()**: Function yang generates human-readable reasons
  - Menjelaskan failure modes: "Failed attempts: X", "High request rate: Y", "Low username diversity: Z"
  - Menjelaskan anomaly: "Anomalous pattern detected: 0.75"
  - Menjelaskan scoring method: "Non-linear boost applied" atau "Adaptive weighting"
  - Menjelaskan history: "Repeat offender: N strikes", "Multiple high-risk periods"
  - Menjelaskan action: "BLOCKED", "RATE LIMITED", "MONITORED"

- **temporal_insight**: Additional insight untuk pattern temporal
  - "High event concentration in single window" jika event_count >= 10
  - "Patterns of recurring attacks detected" jika repeat_incidents >= 2

- **PipelineDecision** sekarang punya field:
  - `reasons`: Tuple of explanation strings
  - `scoring_method`: 'linear', 'boosted', 'adaptive', 'sigmoid'
  - `temporal_insight`: Optional temporal pattern description

### Validasi dan Testing
- Created comprehensive test suite: `tests/test_adversarial_robustness.py`
- **15 tests** covering:
  - Non-linear risk scoring (4 tests)
  - Adversarial scenario detection (4 tests)
  - Temporal feature computation (2 tests)
  - Adaptive watchlist behavior (2 tests)
  - Explainability output (2 tests)
  - End-to-end adversarial detection (1 test)
- ✅ **ALL TESTS PASS** (15/15)

### File Changes Summary
- **Modified**: `hybrid_siem/risk.py` (+120 lines) - Non-linear scoring dengan adaptive & boosting
- **Modified**: `hybrid_siem/scenarios.py` (+60 lines) - Added 4 adversarial scenarios
- **Modified**: `hybrid_siem/watchlist.py` (+80 lines) - Adaptive sensitivity & history tracking
- **Modified**: `hybrid_siem/pipeline.py` (+100 lines) - Explainability & reasoning
- **New**: `hybrid_siem/temporal.py` (+130 lines) - Temporal feature computation
- **Modified**: `hybrid_siem/__init__.py` - Export temporal & enhanced classes
- **New**: `tests/test_adversarial_robustness.py` (+300 lines) - Comprehensive test suite

### Fitur Hasil Phase 3
✅ Non-linear risk scoring dengan conditional boosting
✅ Adaptive weighting based on signal strength
✅ Optional sigmoid transformation untuk smooth blending
✅ 4 adversarial attack scenarios untuk testing robustness
✅ Temporal feature aggregation (rolling, persistence, burst)
✅ Adaptive watchlist dengan repeat offender sensitivity
✅ Full explainability pada setiap decision dengan detailed reasons
✅ Comprehensive test coverage (15 tests, 100% pass)

## Berikutnya
- Implementasi feature importance analysis dari anomaly model untuk understand model behavior
- Testing dengan real SSH logs dari Ubuntu servers
- Fine-tune parameter Isolation Forest (contamination, n_estimators) berdasarkan real data
- Consider supervised evaluation metrics ketika labeled attack data available
- Optimasi performance untuk high-throughput log processing
