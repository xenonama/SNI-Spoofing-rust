
```markdown
<!-- ===== FILE: README_FA.md ===== -->
# SNI Spoofer (Rust + Wails v3)

یک رله‌ی دور زدن DPI که با تزریق TLS ClientHello جعلی و SNI فریب‌دهنده،
ترافیک را از فیلترینگ عبور می‌دهد. این پروژه بازنویسی کامل نسخه‌ی
پایتونی **Patterniha** به زبان Rust است، با رابط کاربری مدرن React +
Tailwind روی Wails v3.

## درباره

برنامه ترافیک TCP را به سرورهای مقصد رله می‌کند و همزمان فیلد SNI را
در Handshake جعل می‌کند. نُه روش مختلف دور زدن DPI پشتیبانی می‌شود، از
تزریق ساده‌ی Wrong Sequence تا تکنیک‌های پیشرفته‌ی Split، Fragmented
و Host-Fake. رابط کاربری شامل نمایش زنده‌ی آمار، کنسول با فیلتر، و
ابزارهای هوشمند برای بررسی Endpointها و SNIهاست.

پروژه‌ی اصلی (پایتون): [patterniha/SNI-Spoofing](https://github.com/patterniha/SNI-Spoofing)

## ویژگی‌ها

- نُه روش دور زدن DPI: `wrong_seq`، `wrong_seq_ttl`، `split_seq`،
  `fragmented`، `padding`، `delayed_retry`، `double_sni`،
  `hostfakesplit`، `fakedsplit`
- چرخش خودکار (`auto`) — یک روش برای هر اتصال
- پروفایل‌های TLS Fingerprint: legacy، Chrome 120/124، Firefox 122/124
- حالت‌های QUIC: `block`، `spoof`، `passthrough`
- آمار زنده: فعال، کل، موفق، ناموفق، ترافیک هر نشست
- کنسول با فیلتر سطح، جستجو، اسکرول خودکار، خروجی
- ابزارهای هوشمند: رتبه‌بندی Endpointها، رتبه‌بندی SNIها، انتخاب سریع‌ترین
- ویرایشگر کانفیگ با ذخیره‌ی اتمیک
- تست Self-Test آفلاین (بدون نیاز به Admin)
- قفل تک‌نمونه (Single-Instance)
- بدون Coil Whine، بدون Electron، فایل اجرایی حدود ۱۲ مگابایت

## معماری

مسیر داده: React → Wails Bindings → سرویس Go → purego → کتابخانه‌ی
Rust → WinDivert.

## پیش‌نیازها

- ویندوز ۱۰/۱۱ (۶۴ بیتی)
- [Rust](https://rustup.rs/) با Toolchain از نوع GNU
- [MinGW-w64](https://www.msys2.org/) برای لینک کردن
- [Go 1.25+](https://go.dev/dl/)
- [Node.js 20+](https://nodejs.org/)
- [Wails v3 CLI](https://v3alpha.wails.io/): `go install github.com/wailsapp/wails/v3/cmd/wails3@latest`
- فایل‌های `WinDivert.dll` و `WinDivert64.sys` (پایین را ببینید)

## ساخت

```cmd
:: موتور Rust
cd engine-ffi
cargo build --release

:: فرانت‌اند
cd ..\gui\frontend
npm install
npm run build

:: اپلیکیشن Wails
cd ..
wails3 generate bindings -ts
go build -ldflags="-H windowsgui -s -w" -o build\bin\sni-gui.exe .

:: کپی DLL موتور کنار فایل اجرایی
copy ..\target\release\sni_engine.dll build\bin\