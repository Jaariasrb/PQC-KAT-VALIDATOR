"""CLI de pqc-kat-validator — comandos: validate, build, fetch-kats."""

from __future__ import annotations

import logging
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from src.harness import LIBRARIES
from src.parser import SUPPORTED_ALGORITHMS, ACVPTestCase, PQCValidatorError
from src.pipeline import ConformanceLevel, Orchestrator
from src.report import ReportGenerator

console = Console()

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS_DIR  = _PROJECT_ROOT / "scripts"
_KAT_DIR      = _PROJECT_ROOT / "kat_vectors"
_REPORTS_DIR  = _PROJECT_ROOT / "reports"

# Colores Rich por nivel de conformancia
_LEVEL_STYLE: dict[str, str] = {
    ConformanceLevel.CONFORMANTE:   "bold green",
    ConformanceLevel.PUNTUAL:       "bold yellow",
    ConformanceLevel.INDETERMINADO: "bold dark_orange",
    ConformanceLevel.SISTEMATICO:   "bold red",
}


def _setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        handlers=[RichHandler(console=console, show_path=False)],
        format="%(message)s",
    )


@click.group()
@click.option("--verbose", "-v", is_flag=True, default=False, help="Activa logs de depuración.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """pqc-kat-validator — validación byte a byte de ML-KEM / ML-DSA / SLH-DSA contra KAT del NIST."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    _setup_logging(verbose)


@cli.command()
@click.option(
    "--algorithm", "-a",
    required=True,
    type=click.Choice(sorted(SUPPORTED_ALGORITHMS), case_sensitive=False),
    help="Algoritmo a validar.",
)
@click.option(
    "--kat-dir", "-k",
    type=click.Path(path_type=Path),
    default=_KAT_DIR,
    show_default=True,
    help="Directorio con los vectores ACVP del NIST.",
)
@click.option(
    "--output", "-o",
    type=click.Path(path_type=Path),
    default=_REPORTS_DIR,
    show_default=True,
    help="Directorio donde se guardan los informes.",
)
@click.option(
    "--library", "-l",
    type=click.Choice(list(LIBRARIES), case_sensitive=False),
    default="liboqs",
    show_default=True,
    help="Librería PQC a validar.",
)
@click.option(
    "--format", "-f", "formats",
    multiple=True,
    type=click.Choice(["json", "txt"], case_sensitive=False),
    default=["json", "txt"],
    show_default=True,
    help="Formato(s) del informe de salida.",
)
@click.pass_context
def validate(
    ctx: click.Context,
    algorithm: str,
    kat_dir: Path,
    output: Path,
    library: str,
    formats: tuple[str, ...],
) -> None:
    """Valida una implementación de algoritmo PQC contra sus vectores KAT del NIST."""
    console.rule(f"[bold cyan]PQC KAT Validator — {algorithm} ({library})[/bold cyan]")
    console.print(f"  Librería : [dim]{library}[/dim]")
    console.print(f"  Vectores : [dim]{kat_dir}[/dim]")
    console.print(f"  Salida   : [dim]{output}[/dim]")
    console.print()

    try:
        orchestrator = Orchestrator(library=library)
    except PQCValidatorError as exc:
        console.print(f"[bold red]Error al inicializar:[/bold red] {exc}")
        sys.exit(1)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task(f"Validando {algorithm}…", total=None)

        def _on_progress(done: int, total: int, case: ACVPTestCase) -> None:
            progress.update(task, completed=done, total=total,
                            description=f"{case.operation.value} tcId={case.tc_id}")

        try:
            run = orchestrator.validate(algorithm, kat_dir, progress_cb=_on_progress)
        except PQCValidatorError as exc:
            console.print(f"[bold red]Error de validación:[/bold red] {exc}")
            sys.exit(1)

    # Mostrar resultado
    report = run.report
    level_style = _LEVEL_STYLE.get(report.level, "white")

    console.print(f"\nNivel de conformancia: [{level_style}]{report.level.value}[/{level_style}]")

    tbl = Table(show_header=True, header_style="bold dim", box=None, padding=(0, 2))
    tbl.add_column("Test cases", justify="right")
    tbl.add_column("Correctos", justify="right")
    tbl.add_column("Fallidos", justify="right")
    tbl.add_column("Tasa de fallo", justify="right")
    tbl.add_row(
        str(report.total_cases),
        f"[green]{report.passed_cases}[/green]",
        f"[red]{report.failed_cases}[/red]" if report.failed_cases else "0",
        f"{report.failure_rate * 100:.1f}%",
    )
    console.print(tbl)

    if run.has_run_errors:
        console.print(
            f"\n[yellow]Advertencia:[/yellow] {len(run.run_errors)} test case(s) no "
            "se pudieron ejecutar por errores del harness (ver informe para detalles)."
        )

    # Generar informes
    try:
        generator = ReportGenerator(output)
        paths = generator.generate_all(run, list(formats))
    except Exception as exc:  # noqa: BLE001
        console.print(f"[bold red]Error al generar informes:[/bold red] {exc}")
        sys.exit(1)

    console.print("\nInformes generados:")
    for fmt, path in paths.items():
        console.print(f"  [{fmt.upper()}] [dim]{path}[/dim]")


@cli.command()
@click.pass_context
def build(ctx: click.Context) -> None:
    """Compila liboqs, el entropy wrapper y los harnesses nativos."""
    script = _SCRIPTS_DIR / "build_liboqs.sh"
    if not script.exists():
        console.print(f"[bold red]Script no encontrado:[/bold red] {script}")
        sys.exit(1)

    console.print(f"[cyan]Ejecutando[/cyan] {script.name}…")
    result = subprocess.run(["bash", str(script)], cwd=_PROJECT_ROOT)
    if result.returncode != 0:
        console.print("[bold red]La compilación falló.[/bold red]")
        sys.exit(result.returncode)
    console.print("[green]Compilación completada.[/green]")


@cli.command("fetch-kats")
@click.option(
    "--output-dir", "-o",
    type=click.Path(path_type=Path),
    default=_KAT_DIR,
    show_default=True,
    help="Directorio donde se copian los vectores ACVP del NIST.",
)
@click.pass_context
def fetch_kats(ctx: click.Context, output_dir: Path) -> None:
    """Copia los vectores KAT (ACVP) del NIST desde el código fuente de liboqs."""
    script = _SCRIPTS_DIR / "fetch_kats.sh"
    if not script.exists():
        console.print(f"[bold red]Script no encontrado:[/bold red] {script}")
        sys.exit(1)

    console.print(f"[cyan]Copiando vectores KAT en[/cyan] {output_dir}…")
    result = subprocess.run(
        ["bash", str(script), str(output_dir)],
        cwd=_PROJECT_ROOT,
    )
    if result.returncode != 0:
        console.print("[bold red]La copia falló.[/bold red]")
        sys.exit(result.returncode)
    console.print("[green]Vectores KAT copiados.[/green]")


if __name__ == "__main__":
    cli()
