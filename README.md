# Port Scanner
TCP/UDP port scanner on python, usong scapy and multiprocessing.

## Usage

```sh
python3 scanner.py [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...
```

Опции `[OPTIONS]` могут быть следующие:

* `--timeout` — таймаут ожидания ответа (по умолчанию 2с)
* `-v, --verbose` — подробный режим
* `-g, --guess` — определение протокола прикладного уровня
