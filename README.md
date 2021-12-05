# Port Scanner
TCP/UDP port scanner on python, usong scapy and multiprocessing.

## Usage

```sh
python3 scanner.py [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...
```

Опции `[OPTIONS]` могут быть следующие:

* `--timeout` — таймаут ожидания ответа (по умолчанию 2с)
* `-v, --verbose` — подробный режим
* `-j, --num_threads` — кол-во потоков(процессов в данной реализации)
* `-g, --guess` — определение протокола прикладного уровня
## Реаллизовано
* UDP-сканирование

* TCP-сканирование TCP SYN с формированием пакетов с использованием scapy


* Распараллеливание через multiprocessing.Pool:


* Доп.фичи:
    - подробный режим
    -  определение протокола прикладного уровня

## Example

```sh
python3 scanner.py -v -g 127.0.0.1 tcp/80 tcp/443 udp/1-100
```
