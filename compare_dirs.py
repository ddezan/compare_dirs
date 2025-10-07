#!/usr/bin/env python3
"""
compare_dirs.py

Compara duas pastas (diretório "mestre" e "pendrive") por hash (SHA-256)
e reporta arquivos adicionados, removidos, alterados e idênticos.

Melhorias:
 - Suporte reforçado a caminhos longos no Windows (\\?\\ prefix)
 - Barra de progresso (tqdm)
 - Resiliente a erros de permissão, encoding e caminhos muito longos
 - Tudo o que é exibido na tela também é salvo em um arquivo de log
"""
from __future__ import annotations
import argparse
import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass
from functools import partial
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Dict, Tuple, Optional, List

from tqdm import tqdm

# ---------- Configurações ----------
HASH_ALGO = "sha256"
CACHE_FILENAME = ".hash_cache.json"
BUFFER_SIZE = 1024 * 1024  # 1MB
DEFAULT_WORKERS = max(1, cpu_count() - 1)
DEFAULT_LOG_FILE = "compare_dirs.log"
# ------------------------------------

logger = logging.getLogger("compare_dirs")


@dataclass
class FileMeta:
    relpath: str
    size: int
    mtime: float
    hash: Optional[str] = None


# ---------- Utilitários de caminho ----------
def long_path(path: Path) -> str:
    """Garante compatibilidade com caminhos longos no Windows."""
    abs_path = os.path.abspath(str(path))
    if os.name == "nt":
        abs_path = abs_path.replace("/", "\\")
        if not abs_path.startswith("\\\\?\\"):
            abs_path = "\\\\?\\" + abs_path
    return abs_path


# ---------- Funções principais ----------
def iter_files(root: Path) -> List[FileMeta]:
    """Percorre o diretório recursivamente e retorna lista de FileMeta."""
    files: List[FileMeta] = []
    for dirpath, _, filenames in os.walk(root):
        for fname in filenames:
            full = Path(dirpath) / fname
            try:
                if full.is_symlink():
                    continue
                stat = full.stat()
                rel = str(full.relative_to(root)).replace(os.sep, "/")
                files.append(FileMeta(relpath=rel, size=stat.st_size, mtime=stat.st_mtime))
            except (OSError, PermissionError) as e:
                logger.warning("Ignorando arquivo inacessível: %s (%s)", full, e)
    return files


def compute_hash_for_file(root: str, meta: FileMeta) -> Tuple[str, Optional[str]]:
    """Calcula hash SHA-256 de um arquivo."""
    full_path = Path(root) / meta.relpath
    full_long = long_path(full_path)
    h = hashlib.new(HASH_ALGO)
    try:
        with open(full_long, "rb") as f:
            while chunk := f.read(BUFFER_SIZE):
                h.update(chunk)
        return meta.relpath, h.hexdigest()
    except Exception:
        # fallback sem prefixo \\?\
        try:
            with open(full_path, "rb") as f:
                while chunk := f.read(BUFFER_SIZE):
                    h.update(chunk)
            return meta.relpath, h.hexdigest()
        except Exception as e2:
            logger.error("Falha ao hashear %s: %s", full_path, e2)
            return meta.relpath, None


def build_map(root: Path, workers: int = DEFAULT_WORKERS,
              use_cache: bool = True, force_rehash: bool = False) -> Dict[str, FileMeta]:
    """Cria um mapa (relpath -> FileMeta com hash) de um diretório."""
    logger.info("Listando arquivos em %s ...", root)
    files = iter_files(root)
    logger.info("Arquivos encontrados: %d", len(files))

    cache_path = Path(root) / CACHE_FILENAME
    cache: Dict[str, Dict] = {}
    if use_cache and cache_path.exists() and not force_rehash:
        try:
            with cache_path.open("r", encoding="utf-8") as fh:
                cache = json.load(fh)
            logger.info("Cache carregado (%s entradas)", len(cache))
        except Exception as e:
            logger.warning("Falha ao carregar cache: %s", e)

    to_hash = []
    result: Dict[str, FileMeta] = {}
    for meta in files:
        cached = cache.get(meta.relpath)
        if cached and not force_rehash and cached.get("size") == meta.size and cached.get("mtime") == meta.mtime:
            meta.hash = cached.get("hash")
            result[meta.relpath] = meta
        else:
            result[meta.relpath] = meta
            to_hash.append(meta)

    logger.info("Arquivos a hashear: %d", len(to_hash))
    if to_hash:
        with Pool(processes=min(workers, len(to_hash))) as pool:
            func = partial(compute_hash_for_file, str(root))
            for relpath, hexhash in tqdm(pool.imap_unordered(func, to_hash),
                                         total=len(to_hash),
                                         desc=f"Hashing {root.name}",
                                         unit="arq",
                                         smoothing=0.05,
                                         dynamic_ncols=True):
                result[relpath].hash = hexhash

    # Salvar cache
    if use_cache:
        new_cache = {m.relpath: {"size": m.size, "mtime": m.mtime, "hash": m.hash}
                     for m in result.values() if m.hash}
        try:
            with cache_path.open("w", encoding="utf-8") as fh:
                json.dump(new_cache, fh, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning("Não foi possível salvar cache: %s", e)

    return result


def compare_maps(master: Dict[str, FileMeta], pen: Dict[str, FileMeta]) -> Dict[str, List[str]]:
    """Compara dois mapas e retorna dict com added, removed, changed, identical."""
    master_set, pen_set = set(master), set(pen)
    added = sorted(pen_set - master_set)
    removed = sorted(master_set - pen_set)
    common = sorted(master_set & pen_set)

    changed, identical = [], []
    for rel in common:
        m, p = master[rel], pen[rel]
        if m.hash != p.hash:
            changed.append(rel)
        else:
            identical.append(rel)

    return {"added": added, "removed": removed, "changed": changed, "identical": identical}


# ---------- Sistema de logging com duplicação ----------
class Tee:
    """Duplica a saída do stdout em arquivo de log."""
    def __init__(self, logfile):
        self.log = open(logfile, "a", encoding="utf-8")
        self.terminal = sys.stdout

    def write(self, message):
        self.terminal.write(message)
        self.log.write(message)
        self.log.flush()

    def flush(self):
        self.terminal.flush()
        self.log.flush()


def setup_logging(verbose: bool = False, logfile: Optional[str] = None):
    level = logging.DEBUG if verbose else logging.INFO
    logger.setLevel(level)

    # handler de console
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    console.setLevel(level)

    # handler de arquivo
    file_handler = logging.FileHandler(logfile, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                                datefmt="%Y-%m-%d %H:%M:%S"))
    file_handler.setLevel(logging.DEBUG)

    logger.addHandler(console)
    logger.addHandler(file_handler)


# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(description="Compara duas pastas por hash (SHA-256).")
    p.add_argument("master", help="Diretório mestre (computador)")
    p.add_argument("pendrive", help="Diretório do pendrive")
    p.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help="Workers para hashing (default: auto)")
    p.add_argument("--no-cache", action="store_true", help="Não usar cache de hashes")
    p.add_argument("--force-rehash", action="store_true", help="Forçar rehash (ignorar cache)")
    p.add_argument("-r", "--report", help="Salvar relatório JSON")
    p.add_argument("--verbose", action="store_true", help="Logs detalhados")
    p.add_argument("--log-file", default=DEFAULT_LOG_FILE, help="Arquivo de log (default: compare_dirs.log)")
    return p.parse_args()


# ---------- Main ----------
def main():
    args = parse_args()

    # Duplica stdout -> log
    sys.stdout = Tee(args.log_file)
    print(f"Iniciando comparação... Log em: {args.log_file}\n")

    setup_logging(args.verbose, args.log_file)

    master, pen = Path(args.master), Path(args.pendrive)
    if not master.is_dir() or not pen.is_dir():
        logger.error("Diretórios inválidos. Verifique os caminhos.")
        sys.exit(1)

    master_map = build_map(master, workers=args.workers, use_cache=not args.no_cache, force_rehash=args.force_rehash)
    pen_map = build_map(pen, workers=args.workers, use_cache=not args.no_cache, force_rehash=args.force_rehash)

    result = compare_maps(master_map, pen_map)
    summary = {
        "added": result["added"],
        "removed": result["removed"],
        "changed": result["changed"],
        "identical_count": len(result["identical"])
    }

    print("\nResumo final:\n")
    print(json.dumps(summary, indent=2, ensure_ascii=False))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        logger.info("Relatório salvo em %s", args.report)

    print(f"\n[✓] Log completo salvo em: {args.log_file}")


if __name__ == "__main__":
    main()
