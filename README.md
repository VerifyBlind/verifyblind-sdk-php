# VerifyBlind PHP

> **Kimliğinizi Kanıtlayın, Gizliliğinizi Koruyun** · _Prove Your Identity, Protect Your Privacy_

**[🇹🇷 Türkçe](#türkçe) · [🇬🇧 English](#english)**

---

## Türkçe

VerifyBlind doğrulama sonucunu kendi PHP sunucunuzda birkaç satırla doğrulamanızı sağlayan resmi kütüphane.
En zor kısım olan RSA-PSS imza kontrolünü (PHP'nin `openssl_verify()` fonksiyonu PSS yapamaz) sizin yerinize yapar.

## Mimari

```
[Web widget'ı / mobil SDK]        ← Doğrulama bitince imzalı `token` verir
        │
        │  POST { token }
        ▼
[Sizin PHP sunucunuz]             ← Bu kütüphane burada çalışır
   1. Enclave imzası (RSA-PSS, SHA-256, salt 32)   → Verifier::verifyToken()
   2. Nonce bir kez tüketilir (sizin deponuzda)     → sizin $consume fonksiyonunuz
   3. Sonuç, SİZİN sorduğunuzla karşılaştırılır     → Verifier::checkAsked()
   (üçü birden: Verifier::verify())
        │
        ▼
   Karar: yaş uygun mu, bu kişi daha önce geldi mi…
```

Kütüphane yalnız **doğrulama** tarafını yapar. Generate aracısı (API anahtarınızı ekleyen ve `validations`'ı
kendi ayarınızdan koyan uç) hâlâ sizdedir; örnek: [example-web-php → `api/generate.php`](https://github.com/VerifyBlind/example-web-php).

## Kurulum

```bash
composer require verifyblind/verifyblind-php
```

PHP 7.4 veya üstü. Tek bağımlılık `phpseclib/phpseclib ~3.0` (saf PHP; ek eklenti ya da `shell_exec` gerekmez,
paylaşımlı hostinglerde de çalışır).

## Hızlı Başlangıç

Doğrulama ucu (`POST /verifyblind/verify`), 15 satır:

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use VerifyBlind\Cache\FileCache;
use VerifyBlind\Exception\VerifyBlindException;
use VerifyBlind\Verifier;

header('Content-Type: application/json');
$token = json_decode(file_get_contents('php://input'), true)['token'] ?? '';
$vb = new Verifier(['cache' => new FileCache()]);
try {
    $result = $vb->verify((string) $token, $consume); // $consume: aşağıda "Nonce kuralı"
} catch (VerifyBlindException $e) {
    http_response_code($e->getHttpStatus());
    exit(json_encode(['error' => $e->getErrorCode()]));
}
// İmza, nonce ve sorulan doğrulamalar kontrol edildi. Artık cevabı kullanabilirsiniz:
echo json_encode(['ok' => true, 'age' => $result->age()]);
```

`$result->userId()`, `nsbdId()`, `docId()` kişiye özel takma kodlardır: veritabanınıza yazın, karar için
`userId()` kullanın (ör. engel listesi), ama **asla loglamayın** (aşağıya bakın).

## Nonce kuralı

Generate çağrısı size bir `nonce` döndürür. Onu **sorduğunuz doğrulamalarla birlikte** saklayın
(Redis/veritabanı, süre **960 saniye**). Doğrulamada aynı nonce **tam bir kez** tüketilir (al ve sil);
bilinmiyorsa, süresi geçtiyse ya da daha önce kullanıldıysa sonuç reddedilir. Bu, aynı token'ın ikinci
kez gönderilmesini (replay) engeller. Depo sizin uygulamanızdadır; kütüphane yalnız bir fonksiyon ister:

```php
// generate aracısında, VerifyBlind nonce döndürdükten sonra:
$pdo->prepare('INSERT INTO vb_nonces (nonce, asked, expires_at) VALUES (?, ?, ?)')
    ->execute([$nonce, json_encode(['age' => '18+', 'user_id' => true]), time() + 960]);

// doğrulamada: tek seferlik al-ve-sil
$consume = function (string $nonce) use ($pdo): ?array {
    $q = $pdo->prepare('SELECT asked FROM vb_nonces WHERE nonce = ? AND expires_at > ?');
    $q->execute([$nonce, time()]);
    $asked = $q->fetchColumn();
    $d = $pdo->prepare('DELETE FROM vb_nonces WHERE nonce = ?');
    $d->execute([$nonce]);
    // Satırı yalnız bir istek silebilir; aynı anda gelen tekrar 0 satır görür ve reddedilir.
    return ($asked !== false && $d->rowCount() === 1) ? json_decode($asked, true) : null;
};
```

Generate ve doğrulama aynı tarayıcı oturumundan geliyorsa (web widget'ı) PHP oturumu da yeter:
`$_SESSION['vb'][$nonce] = $asked;` diye saklayın, doğrulamada okuyup hemen `unset()` edin.

## Sorulan doğrulamalar kuralı

Sonucu **sizin sunucunuzun sorduğuna** göre okuyun; tarayıcının ya da uygulamanın söylediğine asla.
Generate isteğinin gövdesi DevTools'ta değiştirilebilir: `"18+"` yerine `"1+"` soran ziyaretçi, enclave'den
dürüstçe imzalanmış bir `age: true` alır, ama `"1+"` koşulu için. `verify()` (ve tek başına
`Verifier::checkAsked($asked, $validations)`) şunları denetler:

- **Yaş sorduysanız:** `validations.age` true/false olmalı **ve** `validations.age_condition` sorduğunuz
  koşulla birebir aynı olmalı. Eksik ya da farklıysa → ret.
- **Yaş sormadıysanız:** cevapta yaş bulunmamalı.
- **`user_id` sorduysanız:** dolu bir `user_id` gelmeli.

`checkAsked()` sorun yoksa `null`, varsa hata metni döndürür.

**Demo kart:** `validations.is_test: true` ya da `TEST_` ile başlayan kodlar demo karttan gelir (yalnız test
partner'larında). `verify()` bunları varsayılan olarak reddeder; test ortamında `allowTestCards => true` verin.
`$result->isTest()` ile de ayırabilirsiniz.

## İptal webhook'u (revoke)

Kullanıcı VerifyBlind uygulamasında onayını geri çekerse ya da silme isterse VerifyBlind, partner portalı
**Ayarlar**'daki revoke adresinize imzalı bir JSON gönderir. İmza: `"{X-Webhook-Timestamp}.{ham gövde}"`
üzerinde RSA-PSS-SHA256 (salt 32), anahtar `/api/public/webhook-signing-key`. Bu, API anahtarınızla HMAC
**değildir**. Zaman damgası ±5 dakikadan eskiyse reddedilir.

```php
$raw = file_get_contents('php://input'); // ham gövde; yeniden JSON'a çevirmeyin
try {
    $body = $vb->verifyWebhook($raw, $_SERVER['HTTP_X_WEBHOOK_SIGNATURE'] ?? null, $_SERVER['HTTP_X_WEBHOOK_TIMESTAMP'] ?? null);
} catch (VerifyBlindException $e) {
    http_response_code($e->getHttpStatus());
    exit;
}
// $body['nonce'] her zaman vardır; o nonce'a bağlı veriyi silin ya da işaretleyin.
http_response_code(200);
```

Aynı fonksiyon B deseninin (sunucuda çözme) callback imzasını da doğrular; şifreli içeriği çözme bu
kütüphanede yoktur (bkz. [example-web-dotnet](https://github.com/VerifyBlind/example-web-dotnet)).

## Konfigürasyon Parametreleri

| Parametre | Varsayılan | Açıklama |
|---|---|---|
| `apiUrl` | `https://api.verifyblind.com` | VerifyBlind API adresi |
| `keyCacheTtl` | `60` | Enclave anahtarının önbellek süresi (sn). Kısa tutulur: enclave yeniden başlayınca anahtar değişir |
| `webhookKeyCacheTtl` | `3600` | Webhook anahtarının önbellek süresi (sn) |
| `refreshInterval` | `30` | İki zorunlu anahtar tazelemesi arasındaki en kısa süre (sn); bozuk imzalı istekler API'yi yoramaz |
| `cache` | süreç içi bellek | PSR-16 uyumlu `get()`/`set()` olan her nesne (Redis, APCu…) ya da `new FileCache()` |
| `httpGet` | curl / `file_get_contents` | `function (string $url): string` — 200 gövdesini döndürür, aksi hâlde istisna atar |
| `timeout` | `5` | Yerleşik HTTP isteğinin zaman aşımı (sn) |
| `allowTestCards` | `false` | `verify()` demo kart sonucunu kabul etsin mi |
| `webhookTolerance` | `300` | Webhook zaman damgası için izin verilen fark (sn) |

PHP-FPM/Apache'de bellek önbelleği tek istek yaşar; her doğrulama anahtarı bir kez çeker. Bunu önlemek için
`FileCache` ya da kendi PSR-16 önbelleğinizi verin. İmza tutmazsa anahtar bir kez tazelenip tekrar denenir.

### Hata kodları

Tüm istisnalar `VerifyBlind\Exception\VerifyBlindException`'dan türer; `getErrorCode()` sabit bir kod,
`getHttpStatus()` önerilen HTTP durumunu verir.

| Sınıf | Kod | HTTP | Anlamı |
|---|---|---|---|
| `InvalidTokenException` | `bad_token` | 400 | Token biçimi bozuk (base64 JSON `{payload, signature}` değil) |
| `InvalidSignatureException` | `bad_signature` | 401 | İmza tutmuyor (anahtar tazelendikten sonra da) |
| `KeyUnavailableException` | `key_unavailable` | 503 | Anahtar alınamadı ya da okunamadı. Altyapı hatasıdır, token'ın reddi değil |
| `NonceException` | `nonce_invalid` | 401 | Nonce bilinmiyor, süresi geçmiş ya da kullanılmış |
| `AskedMismatchException` | `asked_mismatch` | 401 | Cevap, sorduğunuz doğrulamalarla uyuşmuyor |
| `TestCardException` | `test_card` | 403 | Demo kart sonucu ve `allowTestCards` kapalı |

## Güvenlik Notları

- **Kimlik kodlarını asla loglamayın.** `user_id`, `nsbd_id`, `doc_id` takma adlı kişisel veridir: diğer
  kullanıcı verileriniz gibi koruyun, log'a, hata mesajına ya da analitiğe yazmayın. Kütüphane hiçbir şey
  loglamaz, hata mesajlarında bu kodlar geçmez, `var_dump($result)` / `print_r($result)` da onları gizler.
- **Karar yalnız sunucuda.** Widget'ın `onSuccess` verisine ya da uygulamanın gösterdiğine güvenmeyin;
  `token`'ı sunucunuza gönderip burada doğrulayın.
- **API anahtarı sunucu sırrıdır.** Bu kütüphane API anahtarı istemez; generate aracınızda ortam değişkeninden okuyun.
- `verifySignature()` phpseclib'in süreç genelindeki `RSA::disableSaltLengthDiscovery()` ayarını açar.
  Bu ayar kapalıyken phpseclib başka salt uzunluklarıyla yapılmış imzaları da kabul eder.

## Sürüm Geçmişi

| Sürüm | Değişiklik |
|---|---|
| 1.0.0 | İlk sürüm: `Verifier` (token, nonce, sorulan doğrulamalar, webhook), `Result`, `FileCache` |

---

## English

The official library for verifying a VerifyBlind result on your own PHP server in a few lines. It does the
hard part for you: RSA-PSS signature verification (PHP's `openssl_verify()` cannot do PSS).

### Architecture

```
[Web widget / mobile SDK]         ← Gives you a signed `token` when verification finishes
        │
        │  POST { token }
        ▼
[Your PHP server]                 ← This library runs here
   1. Enclave signature (RSA-PSS, SHA-256, salt 32)  → Verifier::verifyToken()
   2. Nonce consumed exactly once (in your store)    → your $consume function
   3. Answer read against what YOU asked             → Verifier::checkAsked()
   (all three: Verifier::verify())
        │
        ▼
   Decision: old enough? has this person been here before? …
```

The library covers **verification** only. The generate proxy (the endpoint that adds your API key and sets
`validations` from your own configuration) stays in your app; see
[example-web-php → `api/generate.php`](https://github.com/VerifyBlind/example-web-php).

### Installation

```bash
composer require verifyblind/verifyblind-php
```

PHP 7.4 or newer. The only dependency is `phpseclib/phpseclib ~3.0` (pure PHP; no extension or `shell_exec`
needed, so it works on shared hosting).

### Quick Start

Verify endpoint (`POST /verifyblind/verify`), 15 lines:

```php
<?php
require __DIR__ . '/vendor/autoload.php';

use VerifyBlind\Cache\FileCache;
use VerifyBlind\Exception\VerifyBlindException;
use VerifyBlind\Verifier;

header('Content-Type: application/json');
$token = json_decode(file_get_contents('php://input'), true)['token'] ?? '';
$vb = new Verifier(['cache' => new FileCache()]);
try {
    $result = $vb->verify((string) $token, $consume); // $consume: see "Nonce rule" below
} catch (VerifyBlindException $e) {
    http_response_code($e->getHttpStatus());
    exit(json_encode(['error' => $e->getErrorCode()]));
}
// Signature, nonce and asked validations are checked. Now use the answer:
echo json_encode(['ok' => true, 'age' => $result->age()]);
```

`$result->userId()`, `nsbdId()` and `docId()` are pseudonymous person codes: store them, use `userId()` for
decisions (e.g. block lists), and **never log them** (see below).

### Nonce rule

Generate returns a `nonce`. Store it **together with the validations you asked** (Redis/database, TTL
**960 seconds**). At verification the nonce is consumed **exactly once** (get and delete); unknown, expired
or already used means reject. This stops the same token from being replayed. The store lives in your app;
the library only needs a function:

```php
// in the generate proxy, after VerifyBlind returned the nonce:
$pdo->prepare('INSERT INTO vb_nonces (nonce, asked, expires_at) VALUES (?, ?, ?)')
    ->execute([$nonce, json_encode(['age' => '18+', 'user_id' => true]), time() + 960]);

// at verification: one-time get-and-delete
$consume = function (string $nonce) use ($pdo): ?array {
    $q = $pdo->prepare('SELECT asked FROM vb_nonces WHERE nonce = ? AND expires_at > ?');
    $q->execute([$nonce, time()]);
    $asked = $q->fetchColumn();
    $d = $pdo->prepare('DELETE FROM vb_nonces WHERE nonce = ?');
    $d->execute([$nonce]);
    // Only one request can delete the row; a parallel replay sees 0 rows and is rejected.
    return ($asked !== false && $d->rowCount() === 1) ? json_decode($asked, true) : null;
};
```

When generate and verify come from the same browser session (web widget), a PHP session also works:
store `$_SESSION['vb'][$nonce] = $asked;` and read it then `unset()` it at verification.

### Asked-validations rule

Read the answer against **what your server asked**, never against what the browser or app says. The
generate request body can be edited in DevTools: a visitor who changes `"18+"` to `"1+"` gets an honestly
signed `age: true` — for `"1+"`. `verify()` (and on its own `Verifier::checkAsked($asked, $validations)`) checks:

- **Age asked:** `validations.age` must be true/false **and** `validations.age_condition` must equal the asked
  condition exactly. Missing or different → reject.
- **Age not asked:** no age answer may be present.
- **`user_id` asked:** a non-empty `user_id` must be present.

`checkAsked()` returns `null` when the answer matches, or an error text.

**Demo card:** `validations.is_test: true` or codes starting with `TEST_` come from a demo card (test partners
only). `verify()` rejects them by default; pass `allowTestCards => true` on test setups. `$result->isTest()`
tells them apart too.

### Revoke webhook

When a user withdraws consent or asks for erasure in the VerifyBlind app, VerifyBlind POSTs signed JSON to the
revoke URL set in the partner portal **Settings**. Signature: RSA-PSS-SHA256 (salt 32) over
`"{X-Webhook-Timestamp}.{raw body}"`, key from `/api/public/webhook-signing-key`. It is **not** an HMAC with
your API key. Timestamps more than ±5 minutes off are rejected.

```php
$raw = file_get_contents('php://input'); // the raw body; do not re-encode it
try {
    $body = $vb->verifyWebhook($raw, $_SERVER['HTTP_X_WEBHOOK_SIGNATURE'] ?? null, $_SERVER['HTTP_X_WEBHOOK_TIMESTAMP'] ?? null);
} catch (VerifyBlindException $e) {
    http_response_code($e->getHttpStatus());
    exit;
}
// $body['nonce'] is always present; delete or mark the data tied to that nonce.
http_response_code(200);
```

The same method verifies pattern B (server decrypt) callback signatures; decrypting the encrypted response is
not part of this library (see [example-web-dotnet](https://github.com/VerifyBlind/example-web-dotnet)).

### Configuration Parameters

| Option | Default | Description |
|---|---|---|
| `apiUrl` | `https://api.verifyblind.com` | VerifyBlind API base URL |
| `keyCacheTtl` | `60` | Enclave key cache lifetime (s). Short on purpose: the key rotates when the enclave restarts |
| `webhookKeyCacheTtl` | `3600` | Webhook key cache lifetime (s) |
| `refreshInterval` | `30` | Minimum time between two forced key refreshes (s), so bad-signature requests cannot hammer the API |
| `cache` | in-process memory | Any object with PSR-16 `get()`/`set()` (Redis, APCu, …) or `new FileCache()` |
| `httpGet` | curl / `file_get_contents` | `function (string $url): string` — returns the 200 body, throws otherwise |
| `timeout` | `5` | Timeout of the built-in HTTP request (s) |
| `allowTestCards` | `false` | Whether `verify()` accepts demo-card results |
| `webhookTolerance` | `300` | Allowed webhook timestamp difference (s) |

Under PHP-FPM/Apache the memory cache lives for one request, so each verification fetches the key once. Pass
`FileCache` or your own PSR-16 cache to avoid that. When a signature fails, the key is refreshed once and the
check is retried.

#### Error codes

Every exception extends `VerifyBlind\Exception\VerifyBlindException`; `getErrorCode()` gives a stable code and
`getHttpStatus()` a suggested HTTP status.

| Class | Code | HTTP | Meaning |
|---|---|---|---|
| `InvalidTokenException` | `bad_token` | 400 | Malformed token (not base64 JSON `{payload, signature}`) |
| `InvalidSignatureException` | `bad_signature` | 401 | Signature does not verify (also after a key refresh) |
| `KeyUnavailableException` | `key_unavailable` | 503 | Key could not be fetched or read. An infrastructure error, not a rejection |
| `NonceException` | `nonce_invalid` | 401 | Nonce unknown, expired or already used |
| `AskedMismatchException` | `asked_mismatch` | 401 | The answer does not match the validations you asked |
| `TestCardException` | `test_card` | 403 | Demo-card result while `allowTestCards` is off |

### Security Notes

- **Never log identity codes.** `user_id`, `nsbd_id` and `doc_id` are pseudonymous personal data: protect them
  like your other user data and keep them out of logs, error messages and analytics. The library logs nothing,
  its error messages never contain these codes, and `var_dump($result)` / `print_r($result)` hide them.
- **Decide on the server only.** Do not trust the widget's `onSuccess` data or what an app shows; send the
  `token` to your server and verify it here.
- **The API key is a server secret.** This library does not need it; read it from an environment variable in
  your generate proxy.
- `verifySignature()` turns on phpseclib's process-wide `RSA::disableSaltLengthDiscovery()`. Without it
  phpseclib also accepts signatures made with other salt lengths.

### Version History

| Version | Changes |
|---|---|
| 1.0.0 | First release: `Verifier` (token, nonce, asked validations, webhook), `Result`, `FileCache` |

---

## Lisans · License

Apache License 2.0 — bkz. / see [LICENSE](LICENSE).
