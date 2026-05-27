# pqc-kat-validator

Herramienta de validación byte a byte de implementaciones de criptografía post-cuántica (PQC) contra los vectores **KAT** (Known Answer Tests) oficiales del NIST.

> **TFM — Máster en Ciberseguridad · UNIR · 2026**
> Autores: Hernández Martín, A. · Arias Rodríguez, J. · Pons Valmana, J.
> Director: Fidel Paniagua Diez

---

## ¿Qué hace?

Comprueba si tres librerías PQC (**liboqs**, **PQClean** y **pq-crystals**) reproducen exactamente la salida que los estándares NIST exigen cuando se les inyecta una entropía controlada, y clasifica el resultado en uno de cuatro niveles de conformancia.

| Estándar | Algoritmo | Variantes soportadas | Propósito |
|---|---|---|---|
| FIPS 203 | ML-KEM | 512, 768, 1024 | Intercambio de claves |
| FIPS 204 | ML-DSA | 44, 65, 87 | Firma digital basada en lattices |
| FIPS 205 | SLH-DSA | SHA2-128s | Firma basada en hashes |

El **núcleo técnico diferencial** es la inyección determinista de entropía mediante `LD_PRELOAD`, que permite reproducir los KAT sin modificar el código fuente de ninguna librería. Validamos las implementaciones *tal cual*, desde fuera.

---

## Requisitos

- **Linux** (probado en WSL2/Ubuntu). El proyecto no soporta Windows nativo ni macOS — `LD_PRELOAD` y `dlsym(RTLD_NEXT)` son específicos de la familia ELF/glibc.
- Python 3.11+
- CMake 3.16+, GCC (o Clang), `make`, `git`
- Conexión a internet (los scripts clonan liboqs, PQClean, kyber y dilithium)

---

## Quick start

```bash
git clone git@github.com:Jaariasrb/PQC.git pqc-validator
cd pqc-validator
git checkout Develop

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt

./scripts/build_liboqs.sh        # clona y compila liboqs + libkat_entropy.so + harnesses
./scripts/build_pqclean.sh       # 7 binarios PQClean
./scripts/build_pqcrystals.sh    # 6 binarios pq-crystals (sin SLH-DSA)
./scripts/fetch_kats.sh          # copia los vectores ACVP del NIST

# Smoke test — debe terminar con nivel CONFORMANTE
python -m src.cli validate -a ML-KEM-768 -l liboqs
```

El paso más largo es `build_liboqs.sh` (clona y compila liboqs entera con CMake: varios minutos). Los demás son rápidos.

---

## Uso

```bash
# Validar un algoritmo contra una librería
python -m src.cli validate -a ML-KEM-768 -l liboqs
python -m src.cli validate -a ML-DSA-65  -l pqclean
python -m src.cli validate -a ML-KEM-512 -l pqcrystals

# Modo verbose (logs DEBUG)
python -m src.cli -v validate -a ML-KEM-768 -l liboqs

# Atajos a los scripts de build / fetch
python -m src.cli build
python -m src.cli fetch-kats
```

Los informes se generan automáticamente en `reports/` en formato JSON y TXT.

---

## Niveles de conformancia

| Nivel | Tasa de fallo | Significado |
|---|---|---|
| **CONFORMANTE** | 0 % | La implementación reproduce el estándar byte a byte. |
| **PUNTUAL** | < 5 % | Fallos aislados, posiblemente ambientales. |
| **INDETERMINADO** | 5 – 80 % | Comportamiento inconsistente. |
| **SISTEMATICO** | > 80 % | Divergencia estructural respecto al estándar. |

---

## Hallazgos de conformancia

| Librería | ML-KEM | ML-DSA | SLH-DSA |
|---|---|---|---|
| **liboqs** | CONFORMANTE | CONFORMANTE | CONFORMANTE |
| **pqclean** | CONFORMANTE | CONFORMANTE (\*) | INDETERMINADO (\*\*) |
| **pqcrystals** | SISTEMATICO | (SK incompatible con FIPS 204) (\*\*\*) | N/D |

(\*) PQClean ML-DSA usa SK de tamaño expandido (2560 / 4032 / 4896 vs los 2528 / 4000 / 4864 de FIPS 204). Los vectores con contexto no vacío se registran como `RunError`.
(\*\*) PQClean SLH-DSA: keygen CONFORMANTE; firma determinista diverge del estándar en el byte 0 del SPHINCS+-simple en 1 de 13 casos KAT.
(\*\*\*) pq-crystals Dilithium usa formato anterior al estándar (SK 32 bytes mayor). Los `sigGen` con SK de FIPS 204 fallan por tamaño. No cubre SLH-DSA.

**Conclusión científica.** pq-crystals Kyber produce, con el mismo seed, outputs distintos a ML-KEM. El NIST modificó pequeños detalles del esquema al estandarizar, suficientes para romper la equivalencia byte a byte. La herramienta detecta y clasifica esa divergencia de forma reproducible.

---

## Estructura del proyecto

```
src/                       # código Python (plano)
├── cli.py                 → CLI con Click + Rich
├── parser.py              → tipos de dominio + parser ACVP
├── harness.py             → semilla KAT + LD_PRELOAD + ejecución nativa
├── pipeline.py            → comparación byte a byte + clasificación + orquestación
└── report.py              → informes JSON / TXT

native/                    # código C
├── kat_entropy.c          → wrapper LD_PRELOAD (intercepta randombytes/getrandom/getentropy)
├── liboqs/                → harnesses que hablan con liboqs
├── pqclean/               → harnesses genéricos parametrizados con -D
├── pqcrystals/            → harness Dilithium (API con ctx)
└── CMakeLists.txt

scripts/                   # build_liboqs.sh, build_pqclean.sh, build_pqcrystals.sh, fetch_kats.sh
```

---

## Documentación completa

Este README es la portada del proyecto. Para la documentación técnica completa — conceptos fundamentales (PQC, KAT, `LD_PRELOAD`, harness), arquitectura, referencia módulo a módulo, instrucciones de depuración y guía para extender el proyecto — consultar:

**[DOCUMENTACION.md](./DOCUMENTACION.md)**

---

## Lint y tipos

```bash
ruff check .
mypy src/
```

Configuración en `pyproject.toml` (Python 3.11).

---

## Ramas

- **`main`** — versiones estables (entregables del TFM).
- **`Develop`** — rama de trabajo activa del equipo.
