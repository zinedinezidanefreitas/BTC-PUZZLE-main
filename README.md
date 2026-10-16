puzzle.py v3 - varredura ALEATÓRIA (padrão) de chaves privadas em CPU, com secp256k1.

Backends secp256k1 (CPU):
  coincurve  -> libsecp256k1 em C (rápido).  pip install coincurve
  python     -> implementação própria (tabela de janelas + soma de pontos), sem dependências.

Exemplos:
  python puzzle.py -k 20000000000000000:3ffffffffffffffff -a 13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so -w 8
  python puzzle.py -k 20000000000000000:3ffffffffffffffff -a <addr> -s 2 20 -w 8 -f puzzle66.txt
  python puzzle.py -k ... -a <addr> --backend python
  
  py puzzle.py -k 600000000000000000:7fffffffffffffffff -a 1PWo3JeB9jrGwfHDNpdGK54CRas7fsVzXU -s 2 20 -w 8 -f puzzle71.txt
