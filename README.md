# ShareGuard

ShareGuard, paylaşılacak bir proje klasörünü yerel olarak inceleyen Windows
odaklı bir masaüstü uygulamasıdır. Kaynak klasörü değiştirmez; riskli dosyaları,
gizli bilgi adaylarını, kişisel veri adaylarını ve gereksiz geliştirme çıktılarını
gösterir. Kullanıcı isterse dışlamaları uygulayarak temiz bir klasör ve ZIP paketi
oluşturur.

## Özellikler

- `.env`, özel anahtar, API anahtarı ve kod içine yazılmış parola adaylarını bulur.
- E-posta, telefon ve IP adresi gibi kişisel veri adaylarını işaretler.
- Önbellek, sanal ortam, derleme çıktısı ve bağımlılık klasörlerini ayıklar.
- PDF, Office belgesi ve görüntülerde metadata varlığını denetler.
- Temiz kopyayı yeniden tarar ve kritik bulgu kalırsa ZIP üretmez.
- HTML ve JSON raporu ile SHA-256 manifesti oluşturur.
- Sembolik bağlantıları ve Windows junction/reparse noktalarını takip etmez.

ShareGuard desteklenmeyen, şifreli veya okunamayan her içeriği doğrulayamaz.
Sonuçlar paylaşım öncesi insan incelemesinin yerine geçmez.

## Gereksinimler

- Python 3.9 veya üzeri
- Windows 10 ya da Windows 11

## Kaynaktan çalıştırma

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
shareguard
```

Komut satırı giriş noktası yerine `python main.py` da kullanılabilir.

## Windows uygulaması oluşturma

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1
```

Betik kaynakları doğrular, uygulama simgesini üretir ve tek dosyalık Windows
uygulamasını `dist` klasörüne yazar. NSIS kuruluysa kurulum paketi şu komutla
oluşturulabilir:

```powershell
makensis .\scripts\installer.nsi
```

## Gizlilik yaklaşımı

- Tarama yerel makinede gerçekleşir.
- Kaynak dosyalar değiştirilmez.
- Tam eşleşme yalnız uygulama ekranında gösterilir.
- Kaydedilen raporlarda hassas değerler redakte edilir.
- Mutlak kullanıcı yolları raporlara yazılmaz.

## Lisans

Bu proje MIT Lisansı ile sunulur.
