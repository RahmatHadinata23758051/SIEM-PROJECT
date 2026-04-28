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
- Event seperti `Invalid user` dan `pam_unix authentication failure` tetap diparse sebagai konteks, tetapi tidak dihitung sebagai auth attempt untuk menghindari double count.
- Window default feature extraction adalah 60 detik.
- Jika dalam satu window hanya ada satu attempt, `inter_arrival_avg` diisi `window_seconds` agar tetap numerik.

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

## Berikutnya
- Validasi parser dengan log Ubuntu asli yang lebih bervariasi.
- Tambahkan rule thresholds untuk brute force detection.
- Lanjut ke risk scoring dan stateful watchlist.
- Tambahkan evaluasi statistik distribusi synthetic corpus agar threshold rule lebih mudah dikalibrasi.
