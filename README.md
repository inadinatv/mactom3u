# İnadına TV — Mac → M3U Converter

MAC adresi ile giriş yapılan IPTV hesaplarını (Stalker / MAG / Ministra ve MAC-HTTP paneller)
tarayıcıdan, **kurulum gerektirmeden** `.m3u` kanal listesine çeviren tek sayfalık araç.

```
mactom3u/
├── index.html        # Tüm arayüz + istemci mantığı (tek dosya, bağımlılıksız)
├── api/proxy.js      # Serverless proxy — CORS/SSRF engelini aşar, yanıtı normalize eder
├── vercel.json       # Dağıtım ayarları (fonksiyon süresi, güvenlik başlıkları)
├── package.json      # Yalnızca yerel geliştirme/test betikleri (bağımlılık yok)
└── tools/
    ├── dev-server.mjs  # Yerel önizleme sunucusu (Vercel gerekmez)
    └── selftest.mjs    # Bağımlılıksız öz-test (116 doğrulama)
```

## Çalıştırma

```bash
npm run dev     # http://localhost:3000  — index.html + /api/proxy yerel olarak
npm test        # proxy mantığı + M3U üretim hattı için öz-test
```

Vercel'e dağıtımda ek yapılandırma gerekmez: kök dizindeki `index.html` statik olarak,
`api/proxy.js` ise serverless fonksiyon olarak servis edilir.

## Kullanım

1. **Sistem Türü** — paneliniz `play/live.php` ile çalışıyorsa *MAC-HTTP*, MAG/Ministra ise *Stalker Portal*.
2. **Yayın Uzantısı** — `.ts` (standart) veya `.m3u8` (HLS).
3. **Portal URL** — `http://site.com:80` ya da `http://site.com/c/` (şema yazılmasa da tamamlanır).
4. **MAC Adresi** — `00:1A:79:XX:XX:XX` (iki noktalar otomatik eklenir).
5. *Kategorileri Getir* → istediğiniz kategorileri seçin → *M3U Oluştur* → dosyayı adlandırıp kaydedin.

Tarama sırasında ilerleme çubuğu dolduğu gibi **Durdur** düğmesiyle işlem yarıda kesilebilir;
o ana kadar toplanan kanallarla liste yine de oluşturulur.

## v2.4.0 ile gelenler

**Düzeltilen hatalar**

- "Tümünü Seç" ikinci tıklamada çalışmıyordu: `<label for>` tıklamayı kendisi de ilettiği için
  onay kutusu iki kez değişip eski hâline dönüyordu (`preventDefault` ile çözüldü).
- Kategori arama dinleyicisi her bağlantıda yeniden eklendiği için çoğalıyordu; artık bir kez bağlanıyor.
- İndirilen dosyada `URL.createObjectURL` geri bırakılmıyordu (bellek sızıntısı).
- Bozuk `localStorage` kaydı tüm sayfanın açılışını kilitliyordu.
- Portalın döndürdüğü kategori adları `innerHTML`'e ham yazılıyordu (XSS); artık kaçışlanıyor.
- Kanal adındaki `"` karakteri M3U özniteliklerini ve dolayısıyla listeyi bozuyordu.
- `tv_genre_id` döndürmeyen portallarda tüm kanallar "Diğer" grubuna düşüyordu.
- Sayfalamada tekrar eden kanallar listeye iki kez yazılabiliyordu ve `p` parametresini yok sayan
  portallarda döngü sonsuza kadar sürebiliyordu (tekrar eleme + sayfa sınırı eklendi).
- `ftp://` gibi desteklenmeyen şemalar sessizce bozuk bir adrese dönüştürülüyordu.

**Güvenlik / dayanıklılık (proxy)**

- SSRF koruması: iç ağ, loopback, link-local ve bulut metadata adreslerine istek atılmaz.
- 25 sn zaman aşımı + 8 MB yanıt sınırı: fonksiyon asılı kalmaz, `504 / 413` ile açık mesaj döner.
- Handshake sonrası `Authorization: Bearer <token>` da gönderilir (Ministra uyumluluğu).
- Yanıt ayrıştırma genişletildi: saf JSON, `<data>` zarfı, HTML varlığı kodlu zarf ve başında çöp olan JSON.
- Beklenmeyen hatalarda sunucu iç ayrıntısı istemciye sızdırılmaz; tüm yanıtlar `{ js, error }` biçiminde.

**Kullanıcı deneyimi**

- Canlı ilerleme çubuğu (yüzde + bulunan kanal + kategori sayacı) ve taramayı durdurma.
- Portal/MAC alanlarında anında doğrulama, otomatik MAC biçimlendirme, Enter ile hızlı bağlantı.
- Kayıt penceresinde kanal/grup sayısı ve dosya boyutu; ayrıca **Kopyala** düğmesi.
- `alert()` yerine arayüzün diline uyan modal içi uyarı; ESC ile pencere kapatma.
- Ağ hatasında bir kez otomatik yeniden deneme; proxy yoksa (ör. statik barındırma) anlaşılır mesaj.
- Erişilebilirlik ve görünüm: `aria-*` etiketleri, `:focus-visible`, `prefers-reduced-motion`,
  `noscript` uyarısı, favicon, meta/OG etiketleri, boş arama sonucu ekranı.

> Bu araç yalnızca **sahibi olduğunuz veya kullanım hakkı size verilmiş** hesaplar içindir.
