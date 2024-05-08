# Analizator komunikacji sieci bezprzewodowych IEEE 802.11/Wi-Fi

## Opis projektu

Napisany w C analizator komunikacji sieci bezprzewodowych przełącza kartę Wi-Fi w tryb monitorowania, a następnie przechwytuje pakiety przesyłane w sieci. Aplikacja w szczególności nasłuchuje na pakiety `Data` oraz `Beacon` w celu wyświetlenia adresu MAC Access Pointa, nazwy sieci jaką nadaje oraz adresów MAC urządzeń komunikujących się ze sobą za pomocą tego Access Pointa. Aplikacja aktualizuje listę przechwyconych pakietów wraz z każdym nowym pakietem. Jeśli dane urządzenia nie komunikowały się ze sobą w przynajmniej 100 ostatnich pakietach, ich komunikacja zostanie usunięta z listy.

## Zawartość plików

- `main.c` - plik źródłowy aplikacji
- `printutils.h` - plik nagłówkowy z definicjami pomocniczymi przy wyświetlaniu informacji
- `hwutils.h` - plik nagłówkowy z definicjami funkcji pomocniczych do obsługi adresów MAC
- `structs.h` - plik nagłówkowy z definicjami struktur danych związanych z parsowaniem pakietów IEEE 802.11 oraz z definicjami i implementacjami struktur i funkcji pomocniczych do obsługi historii komunikacji

## Kompilacja

```bash
gcc -Wall -I . ./main.c -o ./main.o -lpcap
```

## Uruchomienie

```bash
sudo ./main.o <nazwa_interfejsu>
```