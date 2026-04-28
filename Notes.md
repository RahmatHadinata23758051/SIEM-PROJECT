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

## Ringkasan Implementasi Saat Ini
- Package utama `hybrid_siem` sudah berisi parser, canonical attempt normalizer, feature extractor, dataset builder, synthetic dataset generator, validator, rule detector, risk scorer, watchlist, decision engine, dan processing pipeline.
- Parser SSH sudah mendukung event `failed_password`, `accepted_auth`, `invalid_user`, `pam_auth_failure`, `preauth_disconnect`, dan `client_disconnect`.
- Feature wajib Phase 1 sudah dihasilkan per IP per 60 detik: `failed_count`, `request_rate`, `username_variance`, `inter_arrival_avg`, `failed_ratio`, dan `event_count`.
- CLI dataset builder tersedia untuk mengubah `auth.log` menjadi CSV feature.
- CLI synthetic generator tersedia untuk membuat corpus `mixed` dan `honeypot`.
- CLI validator tersedia untuk membaca CSV feature dan mencetak ringkasan distribusi.

## Artefak Yang Sudah Dibuat
- Sample parser input: `data/samples/auth.log`.
- Sample CSV kecil hasil pipeline: `data/generated/ssh_features.csv`.
- Corpus synthetic `mixed`: `data/generated/synthetic_auth.log` dan `data/generated/synthetic_ssh_features.csv`.
- Corpus synthetic `honeypot`: `data/generated/synthetic_honeypot_auth.log` dan `data/generated/synthetic_honeypot_features.csv`.
- File generated test juga sudah sempat dibuat untuk validasi lokal di `data/generated/`.

## Verifikasi Yang Sudah Dilakukan
- Unit test parser dan feature extraction sudah dibuat.
- Unit test synthetic generator untuk profile `mixed` dan `honeypot` sudah dibuat.
- Unit test detection pipeline dan validation module sudah dibuat.
- Verifikasi lokal terakhir: `python -m unittest discover -s tests -v` lulus.
- Verifikasi generation corpus besar berhasil untuk target CSV sekitar `5 MB` pada dua profile synthetic.

## Status Git
- Source code awal sudah di-commit dan di-push ke branch `main`.
- Artefak besar di `data/generated/` dan cache Python tidak dimasukkan ke git melalui `.gitignore`.

## Berikutnya
- Validasi parser dengan log Ubuntu asli yang lebih bervariasi.
- Kalibrasi threshold rule berdasarkan distribusi corpus synthetic dan log nyata.
- Tambahkan placeholder integrasi anomaly score dari Isolation Forest.
- Pertimbangkan sidecar metadata synthetic bila nanti ingin evaluasi supervised yang lebih eksplisit.
