<p align="center">
  <img src="https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License"/>
  <img src="https://img.shields.io/badge/Recon-Passive%20Only-blue?style=for-the-badge" alt="Passive"/>
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker"/>
</p>

<h1 align="center">PROJECT OVERSEER</h1>
<p align="center"><b>Attack Surface Mapper - Passive Reconnaissance Tool</b></p>

---

```
     ██████╗ ██╗   ██╗███████╗██████╗ ███████╗███████╗███████╗██████╗ 
    ██╔═══██╗██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝██╔══██╗
    ██║   ██║██║   ██║█████╗  ██████╔╝███████╗█████╗  █████╗  ██████╔╝
    ██║   ██║╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══╝  ██╔══╝  ██╔══██╗
    ╚██████╔╝ ╚████╔╝ ███████╗██║  ██║███████║███████╗███████╗██║  ██║
     ╚═════╝   ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝╚═╝  ╚═╝
```

## Sobre

Ferramenta de mapeamento de superfície de ataque externa usando **reconhecimento 100% passivo**. Nenhum pacote é enviado ao alvo,todos os dados vêm de logs públicos de Certificate Transparency e DNS.

**Fase 1 do Cyber Kill Chain: Reconnaissance**

---

## Funcionalidades

| Módulo | Descrição |
|--------|-----------|
| CT Log Enum | Consulta crt.sh, CertSpotter e HackerTarget |
| DNS Resolver | Resolução multi-threaded (50 threads) |
| Geo Intel | Geolocalização de IPs (país, cidade, ISP) |
| Tactical Map | Mapa HTML interativo com priorização de ameaças |

### Priorização de Ameaças

| Cor | Prioridade | Tipo |
|-----|------------|------|
| Vermelho | HIGH | On-Premise/Desconhecido |
| Azul | MEDIUM | VPS Provider |
| Laranja | LOW | CDN/Edge |
| Verde | SAFE | Cloud (AWS/GCP/Azure) |

---

## Instalação

### Python

```bash
git clone https://github.com/seu-usuario/project-overseer.git
cd project-overseer

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

python3 overseer.py --target example.com
```

### Docker

```bash
sudo docker build -t overseer .

mkdir -p output
sudo docker run -v "$(pwd)/output:/app/output" overseer --target example.com --output /app/output/result.html
```

---

## Uso

```bash
# Basico
python3 overseer.py --target tesla.com

# Output customizado
python3 overseer.py --target nubank.com.br --output nubank.html

# Exportar CSV
python3 overseer.py --target example.com --csv dados.csv

# Mais threads
python3 overseer.py --target target.com --threads 100
```

### Opcoes

```
-t, --target    Dominio alvo (obrigatorio)
-o, --output    Arquivo HTML do mapa (default: attack_surface.html)
--csv           Exportar para CSV
--threads       Threads DNS (default: 50)
--timeout       Timeout em segundos (default: 3.0)
--theme         Tema: dark | light (default: dark)
--no-map        Pular geracao do mapa
```

---

## Exemplo de Output

```
$ python3 overseer.py --target nubank.com.br

[+] Found 104 unique subdomains in CT Logs

DNS Resolution: 100% |████████████████████| 105/105
[+] DNS Resolution Complete: 48 alive, 57 dead

[+] Geolocation Complete: 32 located across 3 countries

                RECONNAISSANCE SUMMARY                 
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Metric              ┃ Value                         ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Target Domain       │ nubank.com.br                 │
│ Live Subdomains     │ 48                            │
│ Unique IP Addresses │ 35                            │
│ Countries Spanned   │ 3                             │
└─────────────────────┴───────────────────────────────┘

SAMPLE TARGETS (Potential Shadow IT):
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Subdomain                          ┃ IP            ┃ Location               ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━┩
│ staging-webauthn.api.nubank.com.br │ 44.197.56.100 │ Ashburn, United States │
│ vpn.nubank.com.br                  │ 127.0.0.1     │ ?, ?                   │
└────────────────────────────────────┴───────────────┴────────────────────────┘

[+] Attack Surface Map generated: nubank.html
```

---

## Arquitetura

```
overseer/
├── overseer.py              # CLI principal
├── modules/
│   ├── ct_enum.py           # Enumeracao CT Logs
│   ├── dns_resolver.py      # Resolver DNS multi-threaded
│   ├── geo_intel.py         # Geolocalizacao via ip-api.com
│   └── map_generator.py     # Gerador de mapa Folium
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## Legalidade

| Aspecto | Status |
|---------|--------|
| Scan de portas | NAO usado |
| Pacotes ao alvo | ZERO |
| CT Logs | Publicos |
| DNS | Resolvers publicos |
| Geolocalizacao | Dados publicos |

Reconhecimento passivo apenas. Sem interacao direta com a infraestrutura do alvo.

---

## Disclaimer

```
Esta ferramenta e para fins EDUCACIONAIS e TESTES DE SEGURANCA AUTORIZADOS.

USE para:
- Dominios que voce possui
- Programas de Bug Bounty autorizados  
- Pesquisa de seguranca com permissao

NAO USE para:
- Reconhecimento nao autorizado
- Fins maliciosos

O autor nao se responsabiliza pelo uso indevido.
```

---

## Licenca

MIT License - veja [LICENSE](LICENSE) para detalhes.

---

<p align="center"><b>Red Team Operations - Phase 1: Reconnaissance</b></p>
