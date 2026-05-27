# Documentación técnica — pqc-kat-validator

**TFM Máster en Ciberseguridad · UNIR · 2026**
Autores: Hernández Martín, A. · Arias Rodríguez, J. · Pons Valmana, J.
Director: Fidel Paniagua Diez

---

## Índice

1. [Resumen ejecutivo](#1-resumen-ejecutivo)
2. [Conceptos fundamentales](#2-conceptos-fundamentales)
   1. [Criptografía post-cuántica y por qué hace falta](#21-criptografía-post-cuántica-y-por-qué-hace-falta)
   2. [Los tres estándares del NIST](#22-los-tres-estándares-del-nist)
   3. [Las tres librerías validadas](#23-las-tres-librerías-validadas)
   4. [Qué es un KAT y cómo se distribuye](#24-qué-es-un-kat-y-cómo-se-distribuye)
   5. [El problema de la aleatoriedad y la inyección por LD_PRELOAD](#25-el-problema-de-la-aleatoriedad-y-la-inyección-por-ld_preload)
   6. [Qué es un harness y por qué hay tres familias](#26-qué-es-un-harness-y-por-qué-hay-tres-familias)
   7. [Niveles de conformancia](#27-niveles-de-conformancia)
3. [Arquitectura del sistema](#3-arquitectura-del-sistema)
   1. [Mapa de componentes](#31-mapa-de-componentes)
   2. [Flujo end-to-end de una validación](#32-flujo-end-to-end-de-una-validación)
   3. [Estructura de directorios](#33-estructura-de-directorios)
4. [Referencia de módulos](#4-referencia-de-módulos)
   1. [`src/cli.py` — interfaz de línea de comandos](#41-srcclipy--interfaz-de-línea-de-comandos)
   2. [`src/parser.py` — tipos de dominio y parser ACVP](#42-srcparserpy--tipos-de-dominio-y-parser-acvp)
   3. [`src/harness.py` — inyección de entropía y ejecución nativa](#43-srcharnesspy--inyección-de-entropía-y-ejecución-nativa)
   4. [`src/pipeline.py` — comparación, clasificación y orquestación](#44-srcpipelinepy--comparación-clasificación-y-orquestación)
   5. [`src/report.py` — generación de informes](#45-srcreportpy--generación-de-informes)
   6. [`native/kat_entropy.c` — wrapper LD_PRELOAD](#46-nativekat_entropyc--wrapper-ld_preload)
   7. [Harnesses nativos por librería](#47-harnesses-nativos-por-librería)
   8. [`native/CMakeLists.txt` y scripts de build](#48-nativecmakeliststxt-y-scripts-de-build)
5. [Instalación y uso](#5-instalación-y-uso)
6. [Hallazgos de conformancia](#6-hallazgos-de-conformancia)
7. [Limitaciones conocidas](#7-limitaciones-conocidas)
8. [Cómo depurar el código](#8-cómo-depurar-el-código)
9. [Cómo extender el proyecto](#9-cómo-extender-el-proyecto)
10. [Glosario](#10-glosario)

---

## 1. Resumen ejecutivo

`pqc-kat-validator` es una herramienta de validación **byte a byte** de implementaciones de criptografía post-cuántica (PQC) contra los vectores **KAT** oficiales del NIST. Comprueba si tres librerías distintas — **liboqs**, **PQClean** y **pq-crystals** — reproducen exactamente la salida que el estándar FIPS exige cuando se les inyecta una entropía controlada.

Los algoritmos validados son los tres estandarizados por el NIST en 2024:

| Estándar | Algoritmo | Propósito |
|---|---|---|
| FIPS 203 | ML-KEM-512 / 768 / 1024 | Intercambio de claves (KEM) |
| FIPS 204 | ML-DSA-44 / 65 / 87 | Firma digital (DSA) |
| FIPS 205 | SLH-DSA-SHA2-128s | Firma hash-based |

La herramienta clasifica el comportamiento de cada implementación en uno de cuatro **niveles de conformancia** según el porcentaje de vectores KAT que falla.

El núcleo técnico diferencial es la **inyección determinista de entropía mediante `LD_PRELOAD`**, que permite reproducir los KAT sin modificar el código fuente de ninguna librería. Esto se traduce en una herramienta no invasiva, reproducible y auditable.

---

## 2. Conceptos fundamentales

### 2.1. Criptografía post-cuántica y por qué hace falta

La criptografía asimétrica actual (RSA, ECC) basa su seguridad en problemas matemáticos que un ordenador clásico no puede resolver en tiempo razonable: la factorización de enteros grandes y el logaritmo discreto en curvas elípticas. Un ordenador clásico tardaría miles de millones de años en romper una clave RSA-2048.

El **algoritmo de Shor**, publicado por Peter Shor en 1994, demuestra que un ordenador cuántico suficientemente grande resolvería ambos problemas en tiempo polinómico — minutos u horas en lugar de millones de años. La consecuencia práctica es que toda la criptografía asimétrica desplegada hoy quedará **rota retroactivamente** cuando exista un cuántico operacional de tamaño útil (estimaciones públicas sitúan ese momento entre 2030 y 2040).

El riesgo se materializa **ya hoy** por la estrategia conocida como *harvest now, decrypt later*: un atacante puede grabar tráfico cifrado actual y descifrarlo cuando disponga del cuántico. Los datos con valor a largo plazo (sanitarios, militares, financieros) requieren protección post-cuántica de forma inmediata, antes de que el cuántico exista.

La **criptografía post-cuántica (PQC)** consiste en algoritmos asimétricos basados en problemas matemáticos para los que **no se conoce** ningún algoritmo cuántico eficiente. Los candidatos principales son lattices (retículos), códigos correctores de errores, hashes y multivariadas. El NIST lanzó en 2016 un concurso público para seleccionar los nuevos estándares; el proceso concluyó en 2024 con la publicación de FIPS 203, 204 y 205.

### 2.2. Los tres estándares del NIST

| FIPS | Nombre estándar | Predecesor | Base matemática | Variantes |
|---|---|---|---|---|
| 203 | ML-KEM | Kyber | Lattices (Module-LWE) | 512, 768, 1024 |
| 204 | ML-DSA | Dilithium | Lattices (Module-LWE/SIS) | 44, 65, 87 |
| 205 | SLH-DSA | SPHINCS+ | Hashes (stateless hash-based) | SHA2-128s entre otros |

Los nombres con número (ML-KEM-512, ML-DSA-65...) indican el **nivel de seguridad y los tamaños de parámetros** del esquema. Cuanto más alto el número, mayor seguridad, pero también mayor tamaño de claves y firmas, y más coste computacional.

- **ML-KEM** (Module-Lattice Key Encapsulation Mechanism) sustituye al intercambio de claves Diffie-Hellman. Devuelve a Alice y Bob una clave secreta compartida tras un solo mensaje.
- **ML-DSA** (Module-Lattice Digital Signature Algorithm) sustituye a RSA-signature y ECDSA. Permite firmar mensajes con la clave privada y verificar la firma con la pública.
- **SLH-DSA** (Stateless Hash-based DSA) es una alternativa de firma basada únicamente en funciones hash. Conservador (no asume problemas matemáticos nuevos), pero produce firmas mucho más grandes.

### 2.3. Las tres librerías validadas

| Librería | Mantenedor | Particularidades |
|---|---|---|
| **liboqs** ≥ 0.15.0 | Open Quantum Safe (proyecto comunitario industrial) | Referencia principal del TFM. Implementa los tres estándares al día. |
| **PQClean** | Comunidad de seguridad | Implementaciones de referencia portables, sin optimizaciones específicas, pensadas para auditoría. |
| **pq-crystals** | Equipo CRYSTALS (autores de Kyber y Dilithium) | Código **anterior al estándar final**: implementa Kyber y Dilithium tal como entraron al concurso, no como salieron de él. |

El hecho de validar contra pq-crystals tiene un objetivo académico explícito: documentar cuantitativamente **la divergencia entre las propuestas de competición y los estándares finales**.

### 2.4. Qué es un KAT y cómo se distribuye

**KAT (Known Answer Test)** = test de respuesta conocida. Es una pareja entrada/salida determinista que el NIST publica como referencia: dado un input concreto (semilla, mensaje, clave...), la implementación correcta debe producir un output concreto, byte a byte.

Una analogía sencilla: el NIST funciona como un Ministerio de Educación que quiere comprobar que mil profesores enseñan correctamente. Publica un examen oficial con las respuestas correctas y quien resuelve un problema y no obtiene la respuesta esperada no está enseñando lo que dice enseñar.

Los KAT del NIST para FIPS 203/204/205 se distribuyen en formato **ACVP JSON** (Automated Cryptographic Validation Protocol). Cada fichero `internalProjection.json` contiene:

```jsonc
{
  "vsId": 42,
  "algorithm": "ML-KEM",
  "mode": "keyGen",            // keyGen, encapDecap, sigGen, sigVer
  "revision": "FIPS203",
  "testGroups": [
    {
      "tgId": 1,
      "testType": "AFT",
      "parameterSet": "ML-KEM-512",
      "tests": [
        {
          "tcId": 1,
          "z":  "0A64FDD51A8D91B3166C4958A94EFC3166A4F5DF680980B878DB8371B7624C96",
          "d":  "BBA3C0F5DF044CDF4D9CAA53CA15FDE26F34EB3541555CFC54CA9C31B964D0C8",
          "ek": "1CAB32BE…",   // resultado esperado: clave pública
          "dk": "…"             // resultado esperado: clave privada
        }
      ]
    }
  ]
}
```

- `mode` indica la operación: `keyGen`, `encapDecap`, `sigGen`, `sigVer`.
- `parameterSet` filtra el tamaño exacto (ML-KEM-512 vs ML-KEM-768 vs ML-KEM-1024).
- `tcId` (test case ID) identifica cada par entrada/salida.
- Los campos minúsculos (`z`, `d`, `m`, `seed`, `sk`, `pk`, `message`...) son **inputs**. Los demás (`ek`, `dk`, `c`, `k`, `signature`) son **outputs esperados**.

Los vectores no se descargan del NIST directamente: vienen incluidos en el código fuente de **liboqs**, en `build/liboqs-src/tests/ACVP_Vectors/`. El script `scripts/fetch_kats.sh` los copia a `kat_vectors/` para que el parser Python los encuentre. De este modo validamos contra los vectores oficiales sin depender de mirrors ni descargas externas.

### 2.5. El problema de la aleatoriedad y la inyección por LD_PRELOAD

Los algoritmos PQC son **probabilísticos**: en `keyGen`, en `encaps` y en la firma no determinista, la implementación pide aleatoriedad al sistema operativo para producir resultados distintos cada vez. En condiciones normales eso es deseable; para reproducir un KAT es justo lo que hay que neutralizar.

En Linux, los programas obtienen aleatoriedad llamando a tres funciones del sistema:
- `getrandom(buf, n, flags)` — la syscall estándar moderna del kernel.
- `getentropy(buf, n)` — wrapper de glibc que internamente llama a `getrandom`.
- `randombytes(buf, n)` — API histórica de los KAT del NIST de la competición.

El mecanismo **`LD_PRELOAD`** de Linux permite forzar al loader dinámico a cargar primero una librería compartida nuestra, **antes** que las del sistema. Cuando la librería PQC llama a `getrandom`, el loader resuelve la llamada a la versión que vive en `libkat_entropy.so` en vez de a la del kernel.

Nuestro wrapper (`native/kat_entropy.c`) implementa esas tres funciones de modo que, si la variable de entorno `KAT_SEED_FILE` está definida, devuelven los siguientes bytes del fichero indicado. Si no lo está, delegan en la implementación real (encontrada vía `dlsym(RTLD_NEXT, …)`), de modo que la librería sigue funcionando normalmente fuera del contexto de validación.

Una sola operación (por ejemplo, `keyGen` de ML-DSA) puede pedir aleatoriedad varias veces seguidas. El wrapper mantiene un offset global (`g_seed_offset`): la primera llamada lee los bytes `[0, n)` del fichero, la segunda `[n, n+m)`, etc. La semilla KAT es por tanto la concatenación exacta de toda la aleatoriedad que la operación consume, en orden.

Con este enfoque no se modifica ni una línea de liboqs, PQClean o pq-crystals; se validan tal cual, desde fuera. El resultado refleja el comportamiento real de la librería tal como un usuario final la usaría, sin parches que pudieran ocultar problemas.

### 2.6. Qué es un harness y por qué hay tres familias

Las librerías PQC son código C. Para ejecutarlas hace falta otro programa C que las llame: ese programa puente es el **harness**.

Un harness recibe por línea de argumentos qué operación ejecutar (`keygen`, `encaps`, `decaps`, `sign`, `verify`) y los datos hexadecimales necesarios; llama a la función correspondiente de la librería; e imprime el resultado por stdout en formato `CAMPO: hex`. Es el "piloto" que conduce la librería desde fuera para que el Python pueda interrogarla por subproceso estándar.

Cada librería tiene una API distinta, así que hay un harness por familia:

| Librería | Familia de harnesses | Particularidad |
|---|---|---|
| liboqs | `kem_harness` + `sig_harness` genéricos | Un único binario por familia: liboqs selecciona el algoritmo en tiempo de ejecución por su nombre (`OQS_KEM_new("ML-KEM-768")`). |
| PQClean | `kem_harness.c` + `sig_harness.c` genéricos parametrizados | El **mismo fichero `.c`** se compila siete veces, una por algoritmo, con macros `-D` distintas (`-DKEM_KEYPAIR=PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair`, etc.). Produce siete binarios separados. |
| pq-crystals | `kem_harness.c` (compartido con PQClean) + `sig_harness.c` específico de Dilithium | Dilithium tiene una API con 7 parámetros (incluye `ctx`/`ctxlen`), distinta de PQClean ML-DSA, así que requiere su propio fichero. Seis binarios totales (no implementa SLH-DSA). |

### 2.7. Niveles de conformancia

Los resultados de validar todos los vectores KAT de un algoritmo se reducen a un único nivel, según el porcentaje de fallos:

| Nivel | Tasa de fallo | Significado |
|---|---|---|
| **CONFORMANTE** | exactamente 0 % | La implementación reproduce el estándar byte a byte en todos los vectores. |
| **PUNTUAL** | menor que 5 % | Fallos aislados; probablemente ambientales o casos límite. |
| **INDETERMINADO** | entre 5 % y 80 % (inclusive) | Comportamiento inconsistente; ni claramente correcto ni claramente roto. |
| **SISTEMATICO** | mayor que 80 % | Divergencia estructural respecto al estándar; la implementación no responde a la misma especificación. |

Los umbrales están codificados en `src/pipeline.py`, función `classify()`.

---

## 3. Arquitectura del sistema

### 3.1. Mapa de componentes

El sistema se organiza en tres capas:

**Presentación** — punto de entrada del usuario:
- CLI: `src/cli.py` (Click + Rich).

El CLI termina invocando al orquestador.

**Orquestación (Python)** — núcleo de la herramienta:
- `Orchestrator` (`src/pipeline.py`) recorre los `ACVPTestCase`. Para cada uno: llama a `Harness.run(case)` (`src/harness.py`), compara el resultado con `compare_case(...)` byte a byte y finalmente clasifica el conjunto con `classify(results)` en un `ConformanceLevel`.
- `Parser ACVP` (`src/parser.py`) carga los test cases del directorio de vectores (`load_test_cases(kat_dir)`).
- `Report` (`src/report.py`) genera los informes JSON y TXT con `generate_all`.

**Capa nativa (C, lanzada como subproceso)** — el harness nativo (`kem_harness` o `sig_harness`, según la librería) llama a la librería PQC (liboqs / PQClean / pq-crystals). Cuando esta pide entropía a `getrandom`, `getentropy` o `randombytes`, la intercepta `libkat_entropy.so` (cargada vía `LD_PRELOAD`) y devuelve los bytes del fichero indicado por `KAT_SEED_FILE`.

### 3.2. Flujo end-to-end de una validación

Tomando como ejemplo `python -m src.cli validate -a ML-KEM-768 -l liboqs`:

1. **Click** parsea los argumentos en `src/cli.py:46` (`@click.group()`) y enruta al comando `validate` en `src/cli.py:93`.
2. Se instancia `Orchestrator(library="liboqs")` (`src/pipeline.py:155`) y se llama a `orchestrator.validate(algorithm, kat_dir, progress_cb)`.
3. El orchestrator crea un `Harness("liboqs", "ML-KEM-768")` (`src/harness.py:98`). Esto valida que existe `native/build/liboqs/` y los binarios correspondientes.
4. **`load_test_cases(kat_dir, "ML-KEM-768")`** (`src/parser.py:163`) abre los dos JSON ACVP del KEM (`ML-KEM-keyGen-FIPS203/internalProjection.json` y `ML-KEM-encapDecap-FIPS203/internalProjection.json`), filtra por `parameterSet == "ML-KEM-768"` y devuelve una lista de `ACVPTestCase`.
5. Para cada test case, el orchestrator llama a `_run_case`:
   1. **`Harness.run(case)`** construye la semilla KAT con `_build_seed(case)` (`src/harness.py:31`).
   2. Escribe la semilla en un fichero temporal vía contexto `_seed_file` (autodelete al salir).
   3. Compone el entorno con `LD_PRELOAD=…/libkat_entropy.so` y `KAT_SEED_FILE=/tmp/kat_seed_XXX.bin`.
   4. Lanza el binario nativo apropiado con `subprocess.run([binary, ...args], env=env, timeout=60)`.
   5. El harness en C llama a la API de liboqs (`OQS_KEM_keypair`, `OQS_KEM_encaps`, `OQS_KEM_decaps`).
   6. liboqs pide aleatoriedad → `libkat_entropy.so` la suministra desde el fichero, byte a byte.
   7. El harness imprime el resultado en formato `CAMPO: hex` en stdout.
   8. `_parse_output` (`src/harness.py:85`) convierte ese texto en `{"ek": "…", "dk": "…"}`.
6. **`compare_case(case, actual)`** (`src/pipeline.py:95`) compara los campos esperados con los obtenidos. Si difieren, calcula el primer byte divergente (`_first_diff_byte`). Excepción: campos en `_PLAIN_FIELDS` (solo `verify`) se comparan como texto plano `PASS`/`FAIL`.
7. **Caso especial — firmas no deterministas.** Si la operación es `sign` y `case.deterministic == False`, no se compara la firma byte a byte (cambiará en cada ejecución). En su lugar, `_functional_sign_check` (`src/pipeline.py:186`) verifica la firma recién generada con `verify` y registra el resultado como `PASS`/`FAIL`.
8. Si el subproceso falla (`returncode != 0`, timeout, hex inválido, contexto no soportado…), se captura como **`RunError`** y se incluye en el informe sin contar como fallo KAT.
9. Tras procesar todos los casos, **`classify(algorithm, results)`** (`src/pipeline.py:118`) calcula el porcentaje de fallos y asigna un `ConformanceLevel`.
10. El CLI muestra el resultado en consola con Rich y delega en `ReportGenerator.generate_all(run, ["json", "txt"])` (`src/report.py`).
11. Los informes se escriben en `reports/` con nombre `{algoritmo}_{libreria}_{timestamp}.{ext}`.

### 3.3. Estructura de directorios

```
pqc-validator/
├── src/                       # código Python (estructura plana)
│   ├── cli.py                 # CLI con Click + Rich
│   ├── parser.py              # tipos de dominio + PQCValidatorError + parser ACVP
│   ├── harness.py             # semilla KAT + LD_PRELOAD + ejecución nativa
│   ├── pipeline.py            # comparación byte a byte + clasificación + orquestación
│   └── report.py              # informes JSON / TXT
│
├── native/                    # código C
│   ├── kat_entropy.c          # wrapper LD_PRELOAD (intercepta randombytes/getrandom/getentropy)
│   ├── CMakeLists.txt         # compila libkat_entropy.so + harnesses de liboqs
│   ├── liboqs/
│   │   ├── kem_harness.c      # harness ML-KEM con liboqs (OQS_KEM_*)
│   │   └── sig_harness.c      # harness ML-DSA/SLH-DSA con liboqs (OQS_SIG_*)
│   ├── pqclean/
│   │   ├── kem_harness.c      # harness KEM genérico (PQClean + Kyber, parámetros vía -D)
│   │   └── sig_harness.c      # harness SIG sin ctx (PQClean ML-DSA / SLH-DSA)
│   └── pqcrystals/
│       └── sig_harness.c      # harness SIG con ctx/ctxlen (Dilithium)
│
├── scripts/
│   ├── build_liboqs.sh        # clona y compila liboqs + libkat_entropy.so + harnesses liboqs
│   ├── build_pqclean.sh       # clona PQClean y compila 7 harnesses (uno por algoritmo)
│   ├── build_pqcrystals.sh    # clona kyber + dilithium y compila 6 harnesses
│   └── fetch_kats.sh          # copia los ACVP del NIST desde build/liboqs-src/
│
├── kat_vectors/               # vectores ACVP del NIST (gitignored, generado por fetch_kats.sh)
├── build/                     # liboqs/kyber/dilithium clonados y compilados (gitignored)
├── native/build/              # binarios nativos compilados (gitignored)
├── reports/                   # informes generados (gitignored)
├── venv/                      # entorno virtual de Python (gitignored)
│
├── pyproject.toml             # configuración de ruff (lint) y mypy (tipos)
├── requirements.txt           # dependencias de runtime
├── requirements-dev.txt       # añade ruff y mypy
├── README.md                  # resumen breve del proyecto
└── DOCUMENTACION.md           # este fichero
```

---

## 4. Referencia de módulos

### 4.1. `src/cli.py` — interfaz de línea de comandos

Construido con **Click** (parsing de comandos) y **Rich** (salida coloreada, tablas, barras de progreso). Expone cuatro subcomandos:

| Subcomando | Función | Descripción |
|---|---|---|
| `validate` | `validate()` | Valida un algoritmo contra una librería. |
| `build` | `build()` | Atajo a `scripts/build_liboqs.sh`. |
| `fetch-kats` | `fetch_kats()` | Atajo a `scripts/fetch_kats.sh`. |

**Flag global** `-v` / `--verbose` (en el grupo principal): cambia el nivel de logging de `WARNING` a `DEBUG` y enruta los logs por `RichHandler`.

El comando `validate` recibe:
- `-a` / `--algorithm` *(obligatorio)*: una de las opciones de `SUPPORTED_ALGORITHMS` (case-insensitive).
- `-l` / `--library`: `liboqs` (por defecto), `pqclean` o `pqcrystals`.
- `-k` / `--kat-dir`: directorio de vectores (por defecto `kat_vectors/`).
- `-o` / `--output`: directorio de informes (por defecto `reports/`).
- `-f` / `--format` (multiple): `json`, `txt` (por defecto los dos).

Tras la validación, el CLI muestra una tabla resumen (total, correctos, fallidos, tasa de fallo) coloreada según el nivel (`_LEVEL_STYLE`), advierte de los `run_errors` si los hay y lista las rutas de los informes generados.

### 4.2. `src/parser.py` — tipos de dominio y parser ACVP

Define **toda la nomenclatura del dominio**: enums, dataclasses y la única excepción.

#### Tipos clave

```python
class PQCValidatorError(Exception):
    """Cualquier error del validador: KAT mal formado, algoritmo no soportado,
    fallo del harness, etc."""

class Operation(str, Enum):
    KEYGEN = "keygen"
    ENCAPS = "encaps"
    DECAPS = "decaps"
    SIGN   = "sign"
    VERIFY = "verify"

@dataclass
class ACVPTestCase:
    algorithm: str                      # "ML-KEM-768", etc.
    operation: Operation
    tc_id: int                          # tcId del JSON ACVP
    source: str                         # nombre del directorio ACVP
    inputs:   dict[str, str]            # campos hex que entran al harness
    expected: dict[str, str]            # campos hex que deben salir del harness
    deterministic: bool = False
    prehash: str = "pure"
```

#### Conjuntos de algoritmos soportados

```python
KEM_ALGORITHMS    = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}
MLDSA_ALGORITHMS  = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}
SLHDSA_ALGORITHMS = {"SLH-DSA-SHA2-128s"}
SIG_ALGORITHMS    = MLDSA_ALGORITHMS | SLHDSA_ALGORITHMS
SUPPORTED_ALGORITHMS = KEM_ALGORITHMS | SIG_ALGORITHMS
```

#### Función pública `load_test_cases(kat_dir, algorithm)`

Localiza los directorios ACVP relevantes para el algoritmo, abre cada `internalProjection.json` y delega en `parse_acvp_file()`. Si no encuentra ningún fichero ACVP para el algoritmo, lanza `PQCValidatorError` con un mensaje explícito que indica ejecutar `fetch_kats.sh`.

#### Filtros aplicados durante el parseo (omisiones intencionadas)

`_parse_group()` omite los grupos que no encajan en el alcance del TFM:

- Grupos con `function` distinto de `encapsulation` o `decapsulation` (por ejemplo `encapsulationKeyCheck`).
- En `sigGen`/`sigVer`: grupos con `preHash != "pure"` (no se valida modo HashML-DSA / HashSLH-DSA).
- Grupos con `externalMu == True` o `signatureInterface != "external"` (no se valida modo external-µ).
- Test cases con `deferred == True`.

Las restantes operaciones se materializan en `ACVPTestCase` con los campos exactos que cada modo requiere:

| Modo ACVP | Operation | Inputs típicos | Expected típicos |
|---|---|---|---|
| `keyGen` (KEM) | KEYGEN | `d`, `z` | `ek`, `dk` |
| `keyGen` (ML-DSA) | KEYGEN | `seed` | `pk`, `sk` |
| `keyGen` (SLH-DSA) | KEYGEN | `skSeed`, `skPrf`, `pkSeed` | `pk`, `sk` |
| `encapDecap` (`function=encapsulation`) | ENCAPS | `ek`, `m` | `c`, `k` |
| `encapDecap` (`function=decapsulation`) | DECAPS | `dk`, `c` | `k` |
| `sigGen` | SIGN | `sk`, `pk`, `message`, `context` | `signature` |
| `sigVer` | VERIFY | `pk`, `message`, `signature`, `context` | `verify` (PASS/FAIL) |

### 4.3. `src/harness.py` — inyección de entropía y ejecución nativa

Componente puente entre Python y los binarios nativos. Define la tupla `LIBRARIES = ("liboqs", "pqclean", "pqcrystals")`, constantes operativas (`_TIMEOUT = 60` segundos, `_SIGN_RND = 64` bytes de ceros) y la clase `Harness`.

#### Construcción de la semilla — `_build_seed(case)`

La función reconstruye la entropía que el algoritmo necesita consumir, en el orden correcto. Devuelve `None` si la operación es totalmente determinista (`DECAPS` y `VERIFY` no requieren aleatoriedad):

| Operación | Semilla devuelta |
|---|---|
| `KEYGEN` (KEM) | `d ‖ z` (concatenación) |
| `KEYGEN` (ML-DSA) | `seed` |
| `KEYGEN` (SLH-DSA) | `skSeed ‖ skPrf ‖ pkSeed` |
| `ENCAPS` | `m` |
| `SIGN` (no determinista) | 64 bytes de ceros (ML-DSA randomized) |
| `SIGN` (SLH-DSA determinista) | primera mitad de `pk` (= pkSeed según FIPS 205) |
| `DECAPS`, `VERIFY` | `None` |

El detalle de SLH-DSA con `deterministic == True`: el estándar exige usar la primera mitad de la clave pública como semilla de firma; el código replica ese requisito (`harness.py:43-44`).

#### Preparación del entorno — `_seed_file()` y `_injection_env()`

`_seed_file(case)` es un **context manager**: escribe la semilla en un `NamedTemporaryFile` con prefijo `kat_seed_`, lo `flush`-ea y devuelve la ruta; al salir del bloque, el fichero se borra automáticamente.

`_injection_env(seed_path)` compone un `dict[str, str]` partiendo de `os.environ` y añade:
- `LD_PRELOAD = native/build/libkat_entropy.so`
- `KAT_SEED_FILE = /tmp/kat_seed_XXX.bin`

Si el `.so` no existe, lanza `PQCValidatorError` indicando ejecutar `scripts/build_liboqs.sh`.

#### Clase `Harness`

```python
class Harness:
    def __init__(self, library: str, algorithm: str) -> None: ...
    def run(self, case: ACVPTestCase) -> dict[str, str]: ...
```

- El constructor valida que la librería esté soportada y que exista el directorio de binarios:
  - liboqs → `native/build/liboqs/`
  - pqclean → `native/build/pqclean/{ALGORITMO}/`
  - pqcrystals → `native/build/pqcrystals/{ALGORITMO}/`
- `run(case)` selecciona el binario (`kem_harness` o `sig_harness` según `case.is_kem()`), arma los `argv` con `_args(case)`, gestiona el contexto de semilla y delega en `_exec`.

#### Mapeo de nombres específico de liboqs

```python
_LIBOQS_ALG_NAMES = { "SLH-DSA-SHA2-128s": "SLH_DSA_PURE_SHA2_128S" }
```

liboqs usa internamente un nombre distinto al ACVP para SLH-DSA. Para el resto de algoritmos coincide y no hace falta mapeo.

#### Formato de argumentos al binario

```text
keygen <alg>
encaps <alg> <ek_hex>
decaps <alg> <dk_hex> <c_hex>
sign   <alg> <sk_hex> <msg_hex> [ctx_hex]
verify <alg> <pk_hex> <msg_hex> <sig_hex> [ctx_hex]
```

#### Parsing de la salida — `_parse_output(stdout)`

La salida del harness es texto plano, una línea por campo, en formato `CAMPO: VALOR`. Esta función lo convierte en `dict[str, str]` con claves en minúsculas. Cualquier línea sin formato esperado provoca `PQCValidatorError`.

### 4.4. `src/pipeline.py` — comparación, clasificación y orquestación

Concentra la lógica de "qué es conforme" y orquesta el procesamiento de todos los casos.

#### `class ConformanceLevel(str, Enum)`

```python
CONFORMANTE   = "CONFORMANTE"     # 0 %
PUNTUAL       = "PUNTUAL"         # < 5 %
INDETERMINADO = "INDETERMINADO"   # 5 – 80 %
SISTEMATICO   = "SISTEMATICO"     # > 80 %
```

#### Dataclasses del informe

```python
@dataclass
class FieldResult:
    field: str           # "ek", "dk", "signature", "verify"...
    match: bool
    expected: str        # hex normalizado en mayúsculas
    actual: str
    first_diff_byte: int # offset del primer byte divergente; -1 si match

@dataclass
class CaseResult:
    algorithm: str
    operation: str
    tc_id: int
    fields: list[FieldResult]
    # passed: bool — propiedad: True si todos los fields tienen match
    # failed_fields: list[str] — propiedad: nombres de los fields que no han matched

@dataclass
class ConformanceReport:
    algorithm: str
    level: ConformanceLevel
    total_cases: int
    failed_cases: int
    failure_rate: float
    case_results: list[CaseResult]

@dataclass
class RunError:
    tc_id: int
    operation: str
    error: str

@dataclass
class ValidationRun:
    algorithm: str
    library: str
    kat_dir: Path
    report: ConformanceReport
    run_errors: list[RunError]
```

#### Comparación — `compare_case(case, actual)`

Para cada campo en `case.expected`, normaliza el hex (mayúsculas, validación de longitud par y caracteres válidos) y compara con el valor producido por el harness. Si difieren, calcula el primer byte divergente con `_first_diff_byte`.

El conjunto `_PLAIN_FIELDS = {"verify"}` excluye campos que no son hex: el harness imprime `VERIFY: PASS` o `VERIFY: FAIL`, y la comparación es de texto.

#### Clasificación — `classify(algorithm, results)`

Cuenta fallos, calcula tasa y aplica el árbol de decisión:

```python
level = (CONFORMANTE if rate == 0.0
         else PUNTUAL if rate < 0.05
         else INDETERMINADO if rate <= 0.80
         else SISTEMATICO)
```

Si la lista de resultados está vacía, devuelve `INDETERMINADO` con 0/0.

#### `class Orchestrator`

```python
class Orchestrator:
    def __init__(self, library: str = "liboqs") -> None: ...
    def validate(self, algorithm, kat_dir, progress_cb=None) -> ValidationRun: ...
```

Su método `validate` carga los test cases, itera, ejecuta cada uno, captura `PQCValidatorError` por test case (no aborta — registra `RunError` y sigue), y emite progreso vía callback opcional.

#### Caso especial — firmas no deterministas (ML-DSA)

Cuando `case.operation == SIGN` y `case.deterministic == False`, comparar la firma byte a byte no es posible: cada ejecución produce una firma distinta (firma aleatorizada). El método `_functional_sign_check` (`pipeline.py:186`) toma la firma recién producida y la verifica con `verify` usando la `pk` del propio test case. El resultado se reporta como `verify: PASS` o `verify: FAIL`. La operación se vuelve a etiquetar como `"sign"` en el `CaseResult` para que el informe muestre la operación original.

### 4.5. `src/report.py` — generación de informes

`ReportGenerator(output_dir)` produce hasta dos ficheros por validación, con el patrón de nombre:

```
{algoritmo}_{libreria}_{YYYYMMDDTHHMMSS}.{json|txt}
```

- **JSON** — estructurado, máquina-legible. Incluye metadatos, conformancia, breakdown por operación, lista completa de casos (con `first_diff_byte` y previews de 32 caracteres hex) y `run_errors`.
- **TXT** — informe humano monoespaciado con sección de fallos detallados.

El breakdown por operación se calcula con `_breakdown(run)`: agrupa los `CaseResult` por `operation` (`keygen`, `encaps`, `decaps`, `sign`, `verify`) y cuenta totales / correctos / fallidos por grupo.

### 4.6. `native/kat_entropy.c` — wrapper LD_PRELOAD

Sustituye tres funciones del sistema:

| Función | Origen | Quién la usa |
|---|---|---|
| `randombytes(buf, n)` | API histórica NIST | PQClean (algunas variantes) |
| `getrandom(buf, n, flags)` | syscall Linux | Kernel/glibc moderno |
| `getentropy(buf, n)` | glibc wrapper | liboqs (`OQS_randombytes_system`) |

Las tres funciones leen del fichero indicado por `KAT_SEED_FILE` siguiendo el modelo secuencial: la primera lectura toma los bytes `[0, n)`, la siguiente `[n, n+m)`, etc., manteniendo un offset global en memoria del proceso. Si la semilla se agota antes de tiempo, el wrapper aborta con `abort()` y un mensaje a stderr identificando el offset y los bytes pedidos frente a los disponibles.

Si `KAT_SEED_FILE` no está definida (uso "normal" sin validación), `getrandom` y `getentropy` delegan en la función real obtenida vía `dlsym(RTLD_NEXT, …)`. La librería compartida se compila con `-ldl` para resolver `dlsym`.

A la hora de depurar conviene tener presente que el offset es estático por proceso, no por operación. Cada invocación del harness es un proceso nuevo y empieza con offset 0; eso garantiza que dos test cases consecutivos no se contaminen mutuamente.

### 4.7. Harnesses nativos por librería

#### `native/liboqs/kem_harness.c` y `sig_harness.c`

Usan la API de liboqs:

```c
OQS_KEM *kem = OQS_KEM_new("ML-KEM-768");
OQS_KEM_keypair(kem, ek, dk);
OQS_KEM_encaps(kem, ct, ss, ek);
OQS_KEM_decaps(kem, ss, ct, dk);
OQS_KEM_free(kem);

OQS_SIG *sig = OQS_SIG_new("ML-DSA-65");
OQS_SIG_keypair(sig, pk, sk);
OQS_SIG_sign(sig, signature, &siglen, m, mlen, sk);
OQS_SIG_sign_with_ctx_str(sig, signature, &siglen, m, mlen, ctx, ctxlen, sk);
OQS_SIG_verify(sig, m, mlen, signature, siglen, pk);
OQS_SIG_verify_with_ctx_str(sig, m, mlen, signature, siglen, ctx, ctxlen, pk);
```

Un **único binario** por familia (`kem_harness`, `sig_harness`); el algoritmo se selecciona en runtime por `argv[2]`. Maneja explícitamente el parámetro `ctx` opcional. `verify` siempre devuelve código 0 (PASS/FAIL son ambos resultados válidos del KAT).

#### `native/pqclean/kem_harness.c` y `sig_harness.c`

Genéricos parametrizados por **macros de compilación** (`-D`). El mismo `.c` se compila siete veces, una por algoritmo, inyectando:

```c
-DKEM_KEYPAIR=PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair
-DKEM_PK_BYTES=800
-DKEM_SK_BYTES=1632
-DKEM_CT_BYTES=768
-DKEM_SS_BYTES=32
// ...
```

Cada binario sirve **solo** para su algoritmo (los buffers son arrays de tamaño fijo determinados en compilación).

El `sig_harness.c` de PQClean tiene una limitación conocida: no soporta el parámetro `ctx` de FIPS 204. Si recibe contexto no vacío devuelve error inmediatamente, lo que se traduce en un `RunError` en el informe; el caso se reporta como "no ejecutable", no como fallo KAT. El comentario en el código C es explícito al respecto.

#### `native/pqcrystals/sig_harness.c`

Dilithium (versión actual del repo `pq-crystals/dilithium`) usa una API con 7 parámetros:

```c
extern int SIG_SIGN(uint8_t *sig, size_t *siglen,
                    const uint8_t *m, size_t mlen,
                    const uint8_t *ctx, size_t ctxlen,
                    const uint8_t *sk);
```

El harness pasa siempre `ctx = NULL, ctxlen = 0`. Esto significa que con vectores ACVP que tengan contexto no vacío, el resultado **divergirá** — pero como divergencia algorítmica (no como `RunError`), lo que es semánticamente correcto: Dilithium no implementa el contexto FIPS 204.

#### Tabla de tamaños (verificable en los scripts `build_*.sh`)

| Algoritmo | PK | SK (PQClean) | SK (pq-crystals) | C / sig max |
|---|---|---|---|---|
| ML-KEM-512 | 800 | 1632 | 1632 | 768 |
| ML-KEM-768 | 1184 | 2400 | 2400 | 1088 |
| ML-KEM-1024 | 1568 | 3168 | 3168 | 1568 |
| ML-DSA-44 | 1312 | 2560 | 2560 | 2420 |
| ML-DSA-65 | 1952 | 4032 | 4032 | 3309 |
| ML-DSA-87 | 2592 | 4896 | 4896 | 4627 |
| SLH-DSA-SHA2-128s | 32 | 64 | n/d | 7856 |

> Nota: los tamaños SK que PQClean y pq-crystals usan **no coinciden con FIPS 204** para ML-DSA. Según los autores, FIPS 204 establece SK de 2528 / 4000 / 4864 (para ML-DSA-44 / 65 / 87); PQClean usa el formato "expandido" de 2560 / 4032 / 4896 y pq-crystals usa los mismos tamaños expandidos. La consecuencia es que los vectores ACVP no se pueden inyectar tal cual en `sign` (la SK del KAT tiene tamaño FIPS), lo que se manifiesta como `RunError` o como divergencia, según la librería.

### 4.8. `native/CMakeLists.txt` y scripts de build

**`CMakeLists.txt`** compila dos cosas únicamente:

1. **`libkat_entropy.so`** — librería compartida con `-ldl` para `dlsym(RTLD_NEXT, …)`. Se publica en `native/build/libkat_entropy.so`.
2. **`kem_harness` y `sig_harness` de liboqs** — buscan los headers y la `.so` de liboqs en `LIBOQS_DIR` (por defecto `${CMAKE_SOURCE_DIR}/../build/liboqs`). Salen en `native/build/liboqs/`.

PQClean y pq-crystals **no** pasan por CMake — sus harnesses los compilan `gcc` directamente desde los respectivos scripts shell, porque su modelo es "un binario por algoritmo" parametrizado por defines.

#### `scripts/build_liboqs.sh`

1. Si `build/liboqs-src/` no existe, clona `liboqs 0.15.0` con `--depth 1`.
2. CMake configura e instala liboqs en `build/liboqs/`:
   - `-DBUILD_SHARED_LIBS=ON` `-DOQS_BUILD_ONLY_LIB=ON` `-DOQS_DIST_BUILD=ON`
   - `-DOQS_USE_OPENSSL=OFF` `-DOQS_ALGS_ENABLED=STD` `-DCMAKE_POSITION_INDEPENDENT_CODE=ON`
3. CMake compila `native/` (genera `libkat_entropy.so` + harnesses liboqs).
4. Verifica los artefactos en `native/build/libkat_entropy.so`, `native/build/liboqs/kem_harness`, `native/build/liboqs/sig_harness`.

#### `scripts/build_pqclean.sh`

Clona el repo `PQClean` (branch `master`) y llama a `gcc -O2` siete veces:
- `compile_kem` para ML-KEM-512/768/1024 con `randombytes.c` + `fips202.c`.
- `compile_sig` para ML-DSA-44/65/87 añadiendo `sha2.c`.
- `compile_sig` para SLH-DSA-SHA2-128s (mapeado a `sphincs-sha2-128s-simple`) también con `sha2.c`.

Cada compilación produce `native/build/pqclean/<ALGORITMO>/{kem|sig}_harness`.

#### `scripts/build_pqcrystals.sh`

Clona los repos `pq-crystals/kyber` y `pq-crystals/dilithium` (cada uno usa `KYBER_K` / `DILITHIUM_MODE` para seleccionar el nivel de seguridad en tiempo de compilación):

- `compile_kyber` 3 veces (KYBER_K = 2, 3, 4) con prefijos `pqcrystals_kyber{512|768|1024}_ref_`.
- `compile_dilithium` 3 veces (DILITHIUM_MODE = 2, 3, 5) con prefijos `pqcrystals_dilithium{2|3|5}_ref_`.

Para Kyber **reutiliza el harness genérico `native/pqclean/kem_harness.c`** (API compatible). Para Dilithium usa el harness específico `native/pqcrystals/sig_harness.c` (API de 7 parámetros).

#### `scripts/fetch_kats.sh`

Copia ocho directorios desde `build/liboqs-src/tests/ACVP_Vectors/` a `kat_vectors/`:
- `ML-KEM-keyGen-FIPS203`, `ML-KEM-encapDecap-FIPS203`
- `ML-DSA-keyGen-FIPS204`, `ML-DSA-sigGen-FIPS204`, `ML-DSA-sigVer-FIPS204`
- `SLH-DSA-keyGen-FIPS205`, `SLH-DSA-sigGen-FIPS205`, `SLH-DSA-sigVer-FIPS205`

Cada directorio contiene un `internalProjection.json` con todos los grupos de test (uno por `parameterSet`). El parser filtra por algoritmo en `parse_acvp_file`.

---

## 5. Instalación y uso

### 5.1. Requisitos del sistema

- **Linux** (probado en WSL2/Ubuntu y distribuciones derivadas). El proyecto no soporta Windows nativo ni macOS — `LD_PRELOAD` y `dlsym(RTLD_NEXT)` son específicos de la familia ELF/glibc.
- **Python 3.11+** (probado en 3.12).
- **CMake 3.16+**, **GCC** (o Clang), **make**, **git**.
- Conexión a internet para los clones de liboqs, PQClean, kyber, dilithium.

### 5.2. Instalación desde cero

```bash
git clone <repo> pqc-validator
cd pqc-validator
git checkout Develop

python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -r requirements-dev.txt

./scripts/build_liboqs.sh        # liboqs + libkat_entropy.so + harnesses liboqs
./scripts/build_pqclean.sh       # 7 binarios PQClean
./scripts/build_pqcrystals.sh    # 6 binarios pq-crystals (sin SLH-DSA)
./scripts/fetch_kats.sh          # 8 directorios ACVP
```

El paso más largo es `build_liboqs.sh` (clone + compilación con CMake de liboqs entera): varios minutos. Los demás son rápidos (segundos a 1-2 min).

### 5.3. Comandos del CLI

```bash
# Validar un algoritmo contra una librería (genera JSON/TXT en reports/)
python -m src.cli validate -a ML-KEM-768 -l liboqs
python -m src.cli validate -a ML-DSA-65 -l pqclean
python -m src.cli validate -a ML-KEM-512 -l pqcrystals -f json

# Modo verbose (logs DEBUG con formato Rich)
python -m src.cli -v validate -a ML-KEM-768 -l liboqs

# Atajos a los scripts de build / fetch
python -m src.cli build
python -m src.cli fetch-kats
```

### 5.4. Lint y tipos

```bash
ruff check .       # configuración en pyproject.toml
mypy src/          # Python 3.11
```

---

## 6. Hallazgos de conformancia

Los resultados a continuación corresponden a las validaciones realizadas durante el desarrollo del TFM. Reproducirlos exige ejecutar `python -m src.cli validate -a <ALG> -l <LIB>` para cada celda; la herramienta es determinista, así que dados los mismos vectores ACVP y las mismas versiones de librería deben coincidir.

| Librería | ML-KEM | ML-DSA | SLH-DSA |
|---|---|---|---|
| **liboqs** | CONFORMANTE | CONFORMANTE | CONFORMANTE |
| **pqclean** | CONFORMANTE | CONFORMANTE * | INDETERMINADO ** |
| **pqcrystals** | SISTEMATICO | (SK incompatible con FIPS 204) *** | N/D |

**(\*) PQClean ML-DSA.** SK de tamaño expandido (2560 / 4032 / 4896 bytes vs los 2528 / 4000 / 4864 de FIPS 204). Los vectores ACVP con contexto no vacío (168 de 360 sigGen) se registran como `RunError` porque el harness PQClean SIG no soporta contexto.

**(\*\*) PQClean SLH-DSA.** Keygen CONFORMANTE; firma determinista diverge en el byte 0 del SPHINCS+-simple respecto a FIPS 205 en 1 de 13 casos KAT. Vectores con contexto → `RunError`.

**(\*\*\*) pq-crystals Dilithium.** Tamaños de SK 32 bytes mayores que ML-DSA (formato anterior al estándar). Los `sigGen` con SK de FIPS 204 fallan por tamaño. pq-crystals no cubre SLH-DSA.

El resultado más interesante es el de pq-crystals Kyber: con el mismo seed que ML-KEM produce outputs distintos, SISTEMATICO en todos los tamaños. La conclusión que el TFM documenta es que Kyber ya no equivale a ML-KEM en el plano algorítmico: el NIST modificó pequeños detalles al estandarizar, suficientes para romper la equivalencia byte a byte.

---

## 7. Limitaciones conocidas

Decisiones de scope tomadas durante el desarrollo del TFM, todas documentadas en el código:

1. **Grupos `keyCheck`** (`encapsulationKeyCheck`, `decapsulationKeyCheck`) → omitidos por el parser (`parser.py:74`).
2. **Modos `preHash != pure`** (HashML-DSA, HashSLH-DSA) → omitidos (`parser.py:79`).
3. **Modo `externalMu`** / `signatureInterface != external` → omitidos (`parser.py:82`).
4. **Contexto no vacío en PQClean** → `RunError` (el harness lo rechaza explícitamente).
5. **Contexto no vacío en pq-crystals** → ignorado silenciosamente (siempre se pasa `NULL`).
6. **SLH-DSA no disponible en pq-crystals**.
7. **Solo Linux.** La inyección por `LD_PRELOAD` y `dlsym(RTLD_NEXT)` es específica de la familia ELF/glibc.

---

## 8. Cómo depurar el código

### 8.1. CLI con logs DEBUG

```bash
python -m src.cli -v validate -a ML-KEM-768 -l liboqs 2>&1 | tee /tmp/debug.log
```

La flag `-v` (en el grupo principal, antes del subcomando) sube el nivel de logging a `DEBUG` con `RichHandler`.

### 8.2. Debugger Python desde VS Code

El proyecto incluye `.vscode/launch.json` con dos configuraciones:

- **"Validate: ML-KEM-768 + liboqs (smoke test)"** — caso de control, debe dar CONFORMANTE.
- **"Validate: elegir algoritmo y librería"** — menús desplegables para elegir.

Requiere la extensión **Python** de Microsoft. Las configuraciones usan `${workspaceFolder}/venv/bin/python` como intérprete y `"justMyCode": false` para poder entrar en código de Click, Rich, etc.

**Buenos puntos para breakpoints:**
- `src/cli.py:129` — punto donde arranca el pipeline (`orchestrator.validate(...)`).
- `src/pipeline.py:168` — bucle principal de validación; cada iteración es un test case.
- `src/harness.py:113` — `Harness.run`: aquí se prepara la semilla y se lanza el subproceso.
- `src/pipeline.py:95` — `compare_case`: aquí se compara byte a byte.

### 8.3. Limitación: no se puede depurar el código C desde el debugger Python

Los harnesses C corren en subprocesos separados (`subprocess.run`). El debugger Python sí entra en el código Python que los lanza, pero no en el interior del binario nativo. Para depurar el código C habría que usar `gdb` enganchado al subproceso (fuera del scope habitual de uso del proyecto).

### 8.4. Reproducir manualmente un test case

Para inspeccionar un test case concreto fuera del pipeline Python:

```bash
# 1. Escribir la semilla del KAT en un fichero
echo -n "d_hex_value" | xxd -r -p > /tmp/seed.bin
echo -n "z_hex_value" | xxd -r -p >> /tmp/seed.bin

# 2. Lanzar el harness con LD_PRELOAD apuntando a libkat_entropy.so
LD_PRELOAD=$PWD/native/build/libkat_entropy.so \
KAT_SEED_FILE=/tmp/seed.bin \
./native/build/liboqs/kem_harness keygen ML-KEM-768
```

La salida tiene formato `EK: <hex>` / `DK: <hex>` y se puede comparar manualmente con los valores del JSON ACVP.

---

## 9. Cómo extender el proyecto

### 9.1. Añadir un nuevo algoritmo soportado

1. **`src/parser.py`** — añadir el nombre al `frozenset` correspondiente (`KEM_ALGORITHMS`, `MLDSA_ALGORITHMS` o `SLHDSA_ALGORITHMS`).
2. **Vectores ACVP** — confirmar que están en `kat_vectors/<modo>-FIPSxxx/internalProjection.json` con `parameterSet == <nombre>`. Si no, ampliar `_ACVP_DIRS_*` y `scripts/fetch_kats.sh`.
3. **liboqs** — si el nombre interno difiere del ACVP, añadir entrada a `_LIBOQS_ALG_NAMES` en `src/harness.py`.
4. **PQClean y pq-crystals** — añadir llamadas a `compile_kem` / `compile_sig` en los scripts `build_*.sh` con los tamaños y prefijos correctos.
5. Recompilar y validar.

### 9.2. Añadir una nueva librería

1. **`src/harness.py`** — añadir el identificador a `LIBRARIES` y, en `Harness.__init__`, definir la convención de rutas (`_BUILD / "miLib" / algorithm` u otra).
2. **Harness C** — escribir `kem_harness.c` y/o `sig_harness.c` en `native/<libreria>/` con la API de la nueva librería. Si la API coincide con la de PQClean (3 funciones, sin ctx), reutilizar el genérico parametrizando con `-D`.
3. **Script de build** — crear `scripts/build_<libreria>.sh` siguiendo el patrón de `build_pqclean.sh`.
4. **Validación** — el CLI ya admite cualquier valor presente en `LIBRARIES` sin más cambios.

### 9.3. Añadir un nuevo formato de informe

1. **`src/report.py`** — añadir un método `_xml(self, run, stem, generated_at)` (o similar) que escriba el fichero y devuelva su `Path`.
2. Registrar la rama en `generate_all`.
3. Añadir la opción al `click.Choice` de `--format` en `src/cli.py`.

---

## 10. Glosario

| Término | Significado |
|---|---|
| **ACVP** | Automated Cryptographic Validation Protocol. Formato JSON que el NIST publica para distribuir vectores de prueba criptográficos. |
| **DSA** | Digital Signature Algorithm. En este proyecto, FIPS 204 (ML-DSA) y FIPS 205 (SLH-DSA). |
| **Entropía** | Aleatoriedad criptográfica que un algoritmo consume del sistema operativo. |
| **FIPS** | Federal Information Processing Standards. Estándares publicados por el NIST. |
| **Harness** | Programa puente C que recibe instrucciones por stdin/argv y llama a una librería criptográfica. |
| **KAT** | Known Answer Test. Pareja entrada/salida determinista publicada como referencia. |
| **KEM** | Key Encapsulation Mechanism. Esquema para que dos partes acuerden una clave secreta. FIPS 203 (ML-KEM). |
| **LD_PRELOAD** | Variable de entorno de Linux que fuerza al loader dinámico a buscar símbolos en una librería compartida nuestra antes que en las del sistema. |
| **liboqs** | Open Quantum Safe. Librería criptográfica PQC de referencia. |
| **NIST** | National Institute of Standards and Technology (EE.UU.). Organismo que estandariza FIPS 203/204/205. |
| **PQC** | Post-Quantum Cryptography. Criptografía resistente a ataques con ordenadores cuánticos. |
| **PQClean** | Conjunto de implementaciones de referencia portables, para auditoría. |
| **pq-crystals** | Equipo CRYSTALS, autores de Kyber y Dilithium. Su código es anterior al estándar final. |
| **RunError** | Caso de test que no se pudo ejecutar por un fallo del harness (timeout, hex inválido, API no soportada). Se reporta sin contar como fallo KAT. |
| **Semilla KAT** | Bytes deterministas que sustituyen a la aleatoriedad del SO durante la validación. |
| **SLH-DSA** | Stateless Hash-based DSA. FIPS 205 (variante implementada en este TFM: SHA2-128s). |
| **tcId / tgId** | Test Case ID / Test Group ID del formato ACVP. |
| **vsId** | Vector Set ID del formato ACVP — identificador del fichero completo. |

---

*Última actualización: 2026-05-25.*
