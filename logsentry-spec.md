# LogSentry — SSH/Auth Log Analiz ve Brute-Force Tespit Aracı

> **Claude Code için proje spec dosyası.** Bu dosyayı Claude Code'a ver ve "bu spec'e göre projeyi baştan sona kur" de. Aşağıdaki adımları sırayla uygula, her aşamada test et.

---

## 1. Proje Amacı

Linux sistemlerdeki kimlik doğrulama loglarını (`/var/log/auth.log`, SSH logları) analiz eden, **brute-force saldırılarını ve şüpheli giriş davranışlarını otomatik tespit eden** bir savunma (blue team) aracı. Çıktı olarak renkli bir CLI raporu ve JSON/CSV/HTML export üretir.

**Not:** Bu tamamen savunma amaçlı bir araçtır. Kendi sistemlerinin loglarını analiz etmek, saldırı tespiti ve olay müdahalesi (incident response) içindir.

---

## 2. Teknoloji Stack

- **Dil:** Python 3.8+
- **CLI:** `argparse` (standart kütüphane)
- **Renkli çıktı / tablolar:** `rich`
- **Diğer her şey:** standart kütüphane (`re`, `datetime`, `collections`, `json`, `csv`, `dataclasses`)
- **Test:** `pytest`

Bağımlılıkları minimum tut. Ağır/opsiyonel özellikler (GeoIP gibi) core'u bozmamalı.

---

## 3. Proje Yapısı

```
logsentry/
├── logsentry/
│   ├── __init__.py
│   ├── models.py         # LogEvent, Alert dataclass'ları
│   ├── parser.py         # Log satırlarını parse eder
│   ├── detector.py       # Brute-force + anomali tespiti
│   ├── reporter.py       # CLI / JSON / CSV / HTML çıktı
│   ├── config.py         # Eşik değerleri, varsayılanlar
│   └── cli.py            # argparse entry point
├── tests/
│   ├── test_parser.py
│   ├── test_detector.py
│   └── sample_logs/
│       └── auth.log      # Örnek log verisi
├── examples/
│   └── generate_sample_log.py   # Demo saldırı logu üretir
├── README.md
├── requirements.txt
├── pyproject.toml
├── LICENSE               # MIT
└── .gitignore
```

---

## 4. Veri Modeli (`models.py`)

İki temel dataclass:

**`LogEvent`** — parse edilmiş tek bir log satırı:
- `timestamp: datetime`
- `ip: str`
- `username: str | None`
- `event_type: str` — `"failed"`, `"accepted"`, `"invalid_user"` değerlerinden biri
- `port: int | None`
- `raw: str` — orijinal satır

**`Alert`** — tespit edilen bir tehdit:
- `ip: str`
- `severity: str` — `"LOW"`, `"MEDIUM"`, `"HIGH"`, `"CRITICAL"`
- `alert_type: str` — örn. `"brute_force"`, `"user_enumeration"`, `"successful_breach"`
- `failed_count: int`
- `usernames_tried: list[str]`
- `first_seen: datetime`
- `last_seen: datetime`
- `description: str`

---

## 5. Log Parser (`parser.py`)

### Desteklenecek log satırı formatları

Geleneksel syslog timestamp formatı (`MMM DD HH:MM:SS`) ile başlayan SSH satırları:

```
Nov 12 08:23:45 server sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 54321 ssh2
Nov 12 08:23:47 server sshd[1235]: Failed password for root from 203.0.113.5 port 54322 ssh2
Nov 12 08:24:01 server sshd[1240]: Accepted password for deploy from 10.0.0.8 port 51000 ssh2
Nov 12 08:24:10 server sshd[1241]: Invalid user test from 192.168.1.50
```

### Regex ile çıkarılacak alanlar

Her satır tipi için ayrı regex yaz:

1. **Failed password (invalid user):** `Failed password for invalid user (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)` → `event_type="failed"` + kullanıcı geçersiz
2. **Failed password (valid user):** `Failed password for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)` → `event_type="failed"`
3. **Accepted password:** `Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+) port (\d+)` → `event_type="accepted"`
4. **Invalid user:** `Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)` → `event_type="invalid_user"`

### Gereksinimler

- Timestamp'i parse ederken yıl bilgisi yoksa mevcut yılı varsay (syslog'da yıl olmaz).
- Eşleşmeyen / SSH ile ilgisiz satırları sessizce atla.
- `parse_file(path) -> list[LogEvent]` fonksiyonu, satır satır oku (büyük dosyalar için generator kullan).
- `parse_line(line) -> LogEvent | None` ayrı fonksiyon olsun (test edilebilirlik için).
- IPv4 zorunlu değil; IPv6'yı da yakalayan bir regex bonus olur ama önce IPv4'ü çalıştır.

---

## 6. Tespit Motoru (`detector.py`)

Parse edilmiş `LogEvent` listesini alır, `Alert` listesi döndürür.

### 6.1. Brute-Force Tespiti (kayan zaman penceresi)

- Her IP için başarısız giriş denemelerini zaman damgasına göre grupla.
- **Kural:** Bir IP, `window` saniye içinde `threshold` veya daha fazla başarısız deneme yaptıysa → `brute_force` alarmı.
- Varsayılanlar: `threshold=5`, `window=60` saniye (config'den değiştirilebilir).
- Kayan pencere mantığı: her IP'nin başarısız deneme timestamp'lerini sırala, herhangi bir `window` aralığında `threshold` aşılıyorsa flagle.

### 6.2. User Enumeration / Credential Stuffing

- Bir IP tek pencerede **çok sayıda farklı kullanıcı adı** deniyorsa (örn. 5+ benzersiz username) → `user_enumeration` alarmı.

### 6.3. Başarılı İhlal Şüphesi (EN YÜKSEK ÖNCELİK)

- Bir IP çok sayıda `failed` denemeden **sonra** `accepted` (başarılı giriş) yaptıysa → `successful_breach` alarmı, severity **CRITICAL**.
- Bu, brute-force'un işe yaramış olabileceği anlamına gelir — raporda en tepede gösterilmeli.

### 6.4. Severity Skorlama

| Koşul | Severity |
|---|---|
| Başarısız denemeden sonra başarılı giriş | CRITICAL |
| 50+ başarısız deneme veya 15+ farklı kullanıcı | HIGH |
| 15–49 başarısız deneme | MEDIUM |
| threshold–14 arası başarısız deneme | LOW |

Her `Alert` içine anlamlı bir `description` yaz (örn. "203.0.113.5 adresinden 60 saniyede 23 başarısız giriş, 8 farklı kullanıcı denendi").

---

## 7. Raporlama (`reporter.py`)

### 7.1. CLI Çıktısı (`rich` ile)

- Üstte özet paneli: toplam olay, benzersiz IP sayısı, toplam başarısız deneme, başarılı giriş sayısı, üretilen alarm sayısı.
- Alarm tablosu: `rich.table.Table` ile — sütunlar: **Severity | IP | Tip | Başarısız | Kullanıcılar | İlk Görülme | Son Görülme**.
- Severity'e göre renklendir: CRITICAL=kırmızı, HIGH=turuncu/sarı, MEDIUM=mavi, LOW=gri.
- Alarmları severity'e göre azalan sırala (CRITICAL en üstte).

### 7.2. Export Formatları

- `--format json` → yapısal JSON dosyası
- `--format csv` → CSV
- `--format html` → basit ama şık bir HTML raporu (inline CSS, tablo, severity renkleri). Portföyde ekran görüntüsü olarak çok iyi durur.

---

## 8. Config (`config.py`)

- Varsayılan eşikler: `DEFAULT_THRESHOLD = 5`, `DEFAULT_WINDOW = 60`, `ENUM_THRESHOLD = 5`.
- Severity eşik değerleri.
- CLI parametreleriyle override edilebilir.

---

## 9. CLI Arayüzü (`cli.py`)

`argparse` ile alt komutlar:

```bash
# Temel analiz
logsentry analyze /var/log/auth.log

# Eşik ve pencere ayarı
logsentry analyze auth.log --threshold 10 --window 120

# JSON rapor
logsentry analyze auth.log --format json --output report.json

# Sadece HIGH ve üzeri alarmları göster
logsentry analyze auth.log --min-severity HIGH

# Demo saldırı logu üret (test/tanıtım için)
logsentry generate-sample --output demo.log
```

Parametreler:
- `path` (pozisyonel) — log dosyası
- `--threshold` — brute-force eşiği
- `--window` — saniye cinsinden zaman penceresi
- `--format` — `cli` (varsayılan) / `json` / `csv` / `html`
- `--output` — çıktı dosyası yolu
- `--min-severity` — filtre (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`)

`python -m logsentry` ve mümkünse `logsentry` komutu olarak çalışsın (`pyproject.toml`'da entry point).

---

## 10. Örnek Log Üretici (`examples/generate_sample_log.py`)

Test ve tanıtım için gerçekçi bir `auth.log` üretir:
- Birkaç normal başarılı giriş.
- Bir IP'den yoğun brute-force (30+ başarısız deneme, farklı kullanıcılar).
- Bir IP için "başarısız denemeler sonrası başarılı giriş" senaryosu (CRITICAL alarmı tetiklemek için).
- Rastgele ama tutarlı timestamp'ler.

Bu dosya, README'deki demo için ve `tests/sample_logs/auth.log` için kaynak olur.

---

## 11. Testler (`tests/`)

`pytest` ile:
- **`test_parser.py`:** Her satır formatının doğru parse edildiğini, alanların doğru çıkarıldığını, ilgisiz satırların atlandığını doğrula.
- **`test_detector.py`:** Bilinen bir örnek log verisinde brute-force, user enumeration ve successful_breach alarmlarının doğru üretildiğini; severity skorlamasının doğru çalıştığını doğrula.
- `tests/sample_logs/auth.log` sabit bir test fixture'ı olsun.

En az 8–10 anlamlı test hedefle.

---

## 12. README.md (portföy için kritik)

README profesyonel ve dolu görünmeli. İçerik:
- Proje başlığı + tek cümlelik açıklama + (varsa) rozet/badge'ler.
- **Features** listesi (madde madde yetenekler).
- **Installation:** `pip install -r requirements.txt`.
- **Usage:** yukarıdaki CLI örnekleri.
- **Demo:** `generate-sample` ile üretilmiş log üzerinde örnek çıktı — CLI tablosunun ekran görüntüsü veya kod bloğu.
- **How it works:** tespit mantığının kısa açıklaması (brute-force penceresi, severity skorlama).
- **Disclaimer:** "Bu araç yalnızca kendi sistemlerinizi/yetkili olduğunuz sistemleri analiz etmek içindir."
- **License:** MIT.

Belirgin, temiz İngilizce yaz (uluslararası görünürlük için). Emoji'yi ölçülü kullan.

---

## 13. Build Sırası (Claude Code bunu sırayla yapsın)

1. Proje iskeletini ve `.gitignore`, `LICENSE` (MIT), `requirements.txt`, `pyproject.toml` oluştur.
2. `models.py` — dataclass'ları yaz.
3. `parser.py` — regex'leri ve `parse_line` / `parse_file`'ı yaz. Birkaç manuel satırla hızlı test et.
4. `examples/generate_sample_log.py` — örnek log üret, `tests/sample_logs/auth.log`'a kopyala.
5. `detector.py` — brute-force → user enumeration → successful_breach → severity sırasıyla ekle.
6. `config.py` — eşikleri merkezileştir.
7. `reporter.py` — önce CLI (rich), sonra JSON/CSV/HTML.
8. `cli.py` — argparse ile hepsini bağla.
9. `tests/` — parser ve detector testlerini yaz, `pytest` geçsin.
10. `README.md` — demo çıktısıyla birlikte yaz.
11. Son kontrol: `logsentry analyze` örnek log üzerinde çalışıyor mu, tüm formatlar export ediyor mu, testler geçiyor mu.

---

## 14. Kod Kalitesi Kuralları

- Fonksiyonlara type hint ekle.
- Kısa, anlamlı docstring'ler yaz.
- Sabit değerleri `config.py`'de topla, magic number bırakma.
- Anlamlı değişken/fonksiyon isimleri (İngilizce).
- Büyük dosyalarda bellek dostu ol (generator kullan).

---

## 15. İleride Eklenebilecekler (stretch, opsiyonel — README'de "Roadmap" olarak yaz)

- `--follow` / `-f` ile canlı log takibi (tail modu).
- GeoIP ile IP → ülke eşlemesi (opsiyonel bağımlılık).
- Fail2ban tarzı "engellenecek IP listesi" çıktısı.
- Farklı log kaynakları (nginx access log, Windows Event Log).
- Config dosyası (YAML) desteği.

---

## 16. Claude Code Alt-Ajanları (Subagents) — Geliştirmede Kullan

Bu projeyi Claude Code ile kurarken/geliştirirken işini kolaylaştıracak, göreve göre uzmanlaşmış **alt-ajanlar (subagents)** ekleyebilirsin. Her ajan, kendi izole bağlam penceresinde çalışan, kendi sistem prompt'u olan bir uzman gibidir; Claude Code görevin türüne göre otomatik olarak doğru ajana devreder.

**Nasıl eklenir:** Ajanlar, YAML frontmatter içeren `.md` dosyalarıdır ve iki yerden birine konur:
- `.claude/agents/` → sadece bu projede geçerli (proje bazlı, öncelikli)
- `~/.claude/agents/` → tüm projelerinde geçerli (kullanıcı bazlı)

Ajan dosyası formatı:
```markdown
---
name: agent-adi
description: Bu ajanın ne zaman çağrılacağı
tools: tool1, tool2   # opsiyonel — belirtilmezse tüm araçlara erişir
model: sonnet         # opsiyonel — haiku / sonnet / opus
---
Ajanın sistem prompt'u burada.
```

### 16.1. Bu projeye önerilen ajanlar

Az ama isabetli tut — **5–7 odaklı uzman, her şeyi yapan tek bir ajandan iyidir.** Bu proje için en mantıklıları:

| Ajan | Ne işe yarar (bu projede) |
|---|---|
| **python-pro** / **python-expert** | `parser.py`'deki regex'ler, generator kullanımı, idiomatik ve performanslı Python kodu |
| **security-auditor** | Kendi kodundaki güvenlik açıklarını (input handling, path traversal, injection) denetler — bir güvenlik projesi için portföyde çok anlamlı |
| **code-reviewer** | Her commit sonrası best-practice ve kalite kontrolü |
| **test-automator** | `tests/` altındaki pytest testlerini yazar/genişletir (bölüm 11) |
| **debugger** | Parser veya detector'da hata çıkınca kök-neden analizi |
| **docs-architect** / documentation | README ve dokümantasyonu profesyonelleştirir (portföy için kritik) |

### 16.2. Kaynak repo'lar (buradan alabilirsin)

- **Resmi Claude Code dokümantasyonu (subagents):** https://code.claude.com/docs/en/sub-agents
- **wshobson/agents** — en popüler koleksiyon, plugin marketplace yapısında (python, güvenlik, test, dokümantasyon ajanları dahil): https://github.com/wshobson/agents
- **VoltAgent/awesome-claude-code-subagents** — 150+ ajan, 10 kategoride düzenli, kolay taranabilir: https://github.com/VoltAgent/awesome-claude-code-subagents
- **0xfurai/claude-code-subagents** — 100+ ajan, `python-expert` dahil: https://github.com/0xfurai/claude-code-subagents

### 16.3. Kurulum yöntemleri

**Yöntem A — Plugin marketplace (modern, önerilen):** Claude Code içinde:
```
/plugin marketplace add wshobson/agents
/plugin
```
`/plugin` ile listeden bu projeye uygun paketleri (python, security, testing, documentation) seç ve kur.

**Yöntem B — Manuel .md kopyalama:** İstediğin ajan dosyalarını repo'dan indirip `.claude/agents/` altına koy. Örnek:
```bash
mkdir -p .claude/agents
# İlgili ajanı repo'dan .claude/agents/ içine kopyala
```
Sonra Claude Code'a: *"security-auditor ajanını kullanarak kodu denetle"* diyebilirsin.

**Not:** Bu koleksiyonlar topluluk katkısıdır; ajan dosyalarını `.claude/agents/`'a eklemeden önce içeriğine (özellikle `tools` izinlerine) bir göz at.
