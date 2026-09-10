# SNI-Spoofing-Patterniha (نسخه Rust)

<p align="center">
  <img src="https://img.shields.io/badge/Rust-1.70%2B-orange?style=flat&logo=rust" alt="Rust">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-blue" alt="Platform">
  <img src="https://img.shields.io/badge/License-GPL--3.0-green" alt="License">
</p>

> **پورت کامل و یکپارچه‌ی Rust از پروژه‌ی معروف SNI-Spoofing-Patterniha** — دور زدن سیستم‌های Deep Packet Inspection (DPI) با تزریق TLS ClientHello جعلی و تکنیک‌های پیشرفته‌ی دستکاری هدر TCP/IP.

---

## 📖 درباره‌ی پروژه

این پروژه یک **پورت کامل و بی‌نقص** از [SNI-Spoofing-Patterniha](https://github.com/patterniha/SNI-Spoofing) به زبان **Rust** است. با استفاده از تکنیک‌های مختلف مانند `wrong_seq`، `split_seq`، `fragmented`، `padding`، `hostfakesplit`، `fakedsplit` و موارد دیگر، بسته‌های TLS ClientHello را به‌گونه‌ای دستکاری می‌کند که سیستم‌های DPI قادر به تشخیص SNI واقعی نباشند و ترافیک به‌درستی عبور کند.

### ✨ ویژگی‌های کلیدی

- **یک فایل اجرایی واحد** — ترکیب GUI و بک‌اند در یک فایل `.exe`
- **۹ متد مختلف برای دور زدن DPI** — انتخاب خودکار یا دستی
- **رابط کاربری گرافیکی** — ساخته شده با `egui`/`eframe`
- **پشتیبانی از QUIC** — مسدودسازی، اسپوفینگ یا عبور مستقیم
- **Smart Tools** — رتبه‌بندی اندپوینت‌ها و SNIها بر اساس تأخیر
- **Scoreboard زنده** — نمایش آمار موفقیت/شکست به‌صورت لحظه‌ای
- **تست‌های آفلاین** — اجرای `--self-test` بدون نیاز به ادمین یا WinDivert
- **پروفایل‌های TLS** — شبیه‌سازی فینگرپرینت مرورگرهای Chrome و Firefox
- **حالت Trojan + Xray** — پشتیبانی از پروکسی SOCKS5 و HTTP

---

## 🚀 نحوه‌ی اجرا

### پیش‌نیازها

- **ویندوز ۱۰/۱۱** (۶۴ بیتی) — بهترین عملکرد
- **دسترسی Administrator** — برای اجرای WinDivert ضروری است
- فایل‌های `WinDivert.dll` و `WinDivert64.sys` — [دانلود از صفحه‌ی رسمی](https://github.com/basil00/Divert/releases)

### اجرا

1. فایل `sni-gui.exe` را از [صفحه‌ی Releases](https://github.com/xenonama/SNI-Spoofing-rust/releases) دانلود کنید.
2. فایل‌های `WinDivert.dll` و `WinDivert64.sys` را کنار `sni-gui.exe` قرار دهید.
3. یک فایل `config.json` معتبر در همان پوشه ایجاد کنید (یا از نمونه استفاده کنید).
4. **برنامه را با دسترسی Administrator اجرا کنید** (راست‌کلیک → Run as administrator).

### اجرا از طریق خط فرمان

```bash
sni-gui.exe --config config.json --log-level DEBUG
