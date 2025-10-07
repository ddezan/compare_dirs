#!/usr/bin/env python3
"""
compare_dirs.py

Compara duas pastas (diretório "mestre" e "pendrive") por hash (SHA-256)
e reporta arquivos adicionados, removidos, alterados e idênticos.

Melhorias desta versão:
 - Suporte a caminhos longos no Windows (\\?\\ prefix)
 - Barra de progresso (tqdm) durante o hashing
 - Mais robusto a erros de permissão e encoding
"""
from __future__ import annotations
import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
from dataclasses import dataclass
from functools import partial
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Dict, Tuple, Optional, List

from tqdm import tqdm  # <--- novo

# ---------- Configurações ----------
HASH_ALGO = "sha256"
CACHE_FILENAME = ".hash_cache.json"
BUFFER_SIZE = 1024 * 1024  # 1MB
DEFAULT_WORKERS = max(1, cpu_count() - 1)
# ------------------------------------

logger = logging.getLogger("compare_dirs")


@dataclass
class FileMeta:
    relpath: str
    size: int
    mtime: float
    hash: Optional[str] = None


def long_path(path: Path) -> str:
    """Garante compatibilidade com caminhos longos no Windows."""
    abs_path = str(path.resolve())
    if os.name == "nt":
        abs_path = abs_path.replace("/", "\\")
        if not abs_path.startswith("\\\\?\\"):
            abs_path = "\\\\?\\" + abs_path
    return abs_path


def iter_files(root: Path) -> List[FileMeta]:
    """Percorre o diretório recursivamente e retorna lista de FileMeta."""
    root = root.resolve()
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
            except (OSError, PermissionError):
                logger.warning("Ignorando arquivo inacessível: %s", full)
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
    except Exception as e:
        logger.error("Falha ao hashear %s: %s", full_path, e)
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
                                         unit="arq"):
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


def setup_logging(verbose: bool = False):
    """Configura logs coloridos e claros."""
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.setLevel(level)
    if not logger.handlers:
        logger.addHandler(handler)


def parse_args():
    p = argparse.ArgumentParser(description="Compara duas pastas por hash (SHA-256).")
    p.add_argument("master", help="Diretório mestre (computador)")
    p.add_argument("pendrive", help="Diretório do pendrive")
    p.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS, help="Workers para hashing (default: auto)")
    p.add_argument("--no-cache", action="store_true", help="Não usar cache de hashes")
    p.add_argument("--force-rehash", action="store_true", help="Forçar rehash (ignorar cache)")
    p.add_argument("-r", "--report", help="Salvar relatório JSON")
    p.add_argument("--verbose", action="store_true", help="Logs detalhados")
    return p.parse_args()


def main():
    args = parse_args()
    setup_logging(args.verbose)

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

    print(json.dumps(summary, indent=2, ensure_ascii=False))

    if args.report:
        with open(args.report, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        logger.info("Relatório salvo em %s", args.report)


if __name__ == "__main__":
    main()
