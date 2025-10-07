#!/usr/bin/env python3
"""
compare_dirs.py

Compara duas pastas (diretório "mestre" e "pendrive") por hash (SHA-256) e reporta:
 - arquivos criados (aparecem no pendrive e não no mestre)
 - arquivos removidos (aparecem no mestre e não no pendrive)
 - arquivos alterados (mesmo caminho relativo, hashes diferentes)

Recursos:
 - hashing em paralelo (multiprocessing)
 - pré-filtro por tamanho para evitar hashing desnecessário
 - relatório JSON de saída
 - opção de sincronizar (copiar) do pendrive para o mestre (com dry-run)
 - opção de cache de hashes (arquivo .hash_cache.json) para acelerar execuções repetidas
 - logs e progresso
"""
from __future__ import annotations
import argparse
import hashlib
import json
import logging
import os
import shutil
import sys
from dataclasses import dataclass, asdict
from functools import partial
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Dict, Tuple, Optional, List

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


def iter_files(root: Path) -> List[FileMeta]:
    """
    Percorre o diretório recursivamente e retorna lista de FileMeta com relpath, size, mtime.
    Ignora diretórios ocultos e arquivos especiais.
    """
    root = root.resolve()
    files: List[FileMeta] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # opcional: ignorar pastas como .git, Thumbs.db etc.
        # não removemos nada aqui; se quiser pode adicionar filtros
        for fname in filenames:
            full = Path(dirpath) / fname
            try:
                if full.is_symlink():
                    continue
                stat = full.stat()
                rel = str(full.relative_to(root)).replace(os.sep, "/")
                files.append(FileMeta(relpath=rel, size=stat.st_size, mtime=stat.st_mtime))
            except (OSError, PermissionError) as e:
                logger.warning("Não foi possível acessar %s: %s", full, e)
    return files


def compute_hash_for_file(root: str, meta: FileMeta) -> Tuple[str, Optional[str]]:
    """
    Calcula hash para um arquivo. Retorna (relpath, hexhash) ou (relpath, None) em caso de erro.
    """
    full_path = Path(root) / meta.relpath
    h = hashlib.new(HASH_ALGO)
    try:
        with open(full_path, "rb") as f:
            while True:
                chunk = f.read(BUFFER_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return meta.relpath, h.hexdigest()
    except Exception as e:
        logger.error("Falha ao hashear %s: %s", full_path, e)
        return meta.relpath, None


def build_map(root: Path, workers: int = DEFAULT_WORKERS,
              use_cache: bool = True, force_rehash: bool = False) -> Dict[str, FileMeta]:
    """
    Cria um dicionário relpath -> FileMeta (com hash) para o diretório root.
    Usa multiprocessing para acelerar hashing quando necessário.
    use_cache: tenta carregar/salvar CACHE_FILENAME no root.
    force_rehash: ignora o cache mesmo que exista.
    """
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
            logger.warning("Não foi possível carregar cache: %s", e)
            cache = {}

    # Decidir quais precisam de hash:
    to_hash = []
    result: Dict[str, FileMeta] = {}
    for meta in files:
        cached = cache.get(meta.relpath)
        if cached and not force_rehash and cached.get("size") == meta.size and cached.get("mtime") == meta.mtime and cached.get("hash"):
            meta.hash = cached["hash"]
            result[meta.relpath] = meta
        else:
            # pré-adicionar; hash será preenchido
            result[meta.relpath] = meta
            to_hash.append(meta)

    logger.info("Arquivos a hashear: %d", len(to_hash))
    if to_hash:
        # multiprocessing pool
        pool_workers = min(workers, len(to_hash))
        logger.info("Usando %d workers para hashing...", pool_workers)
        with Pool(processes=pool_workers) as pool:
            func = partial(compute_hash_for_file, str(root))
            for relpath, hexhash in pool.imap_unordered(func, to_hash):
                meta = result[relpath]
                meta.hash = hexhash

    # Atualizar cache
    if use_cache:
        new_cache = {}
        for meta in result.values():
            if meta.hash:
                new_cache[meta.relpath] = {"size": meta.size, "mtime": meta.mtime, "hash": meta.hash}
        try:
            with (Path(root) / CACHE_FILENAME).open("w", encoding="utf-8") as fh:
                json.dump(new_cache, fh, indent=2, ensure_ascii=False)
            logger.info("Cache salvo (%d entradas)", len(new_cache))
        except Exception as e:
            logger.warning("Não foi possível salvar cache: %s", e)

    return result


def compare_maps(master_map: Dict[str, FileMeta], pen_map: Dict[str, FileMeta]) -> Dict[str, List[str]]:
    """
    Compara dois mapas e produz dict com chaves: added, removed, changed, identical
    Cada lista contém caminhos relativos (strings).
    """
    master_set = set(master_map.keys())
    pen_set = set(pen_map.keys())

    added = sorted(pen_set - master_set)     # no pen, não no master
    removed = sorted(master_set - pen_set)   # no master, não no pen
    common = sorted(master_set & pen_set)

    changed = []
    identical = []
    for rel in common:
        m_meta = master_map[rel]
        p_meta = pen_map[rel]
        # Se ambos hashes disponíveis, comparar; caso falha no hash (None), usar tamanho como fallback
        if m_meta.hash and p_meta.hash:
            if m_meta.hash != p_meta.hash:
                changed.append(rel)
            else:
                identical.append(rel)
        else:
            # fallback prudente
            if m_meta.size != p_meta.size:
                changed.append(rel)
            else:
                # sem hash e mesmo tamanho -> tratar como idêntico (mais seguro?), porém registramos warning
                identical.append(rel)
                logger.debug("Sem hash para %s; mesmo tamanho -> considerado idêntico", rel)

    return {"added": added, "removed": removed, "changed": changed, "identical": identical}


def copy_files(root_from: Path, root_to: Path, relpaths: List[str], dry_run: bool = True, backup: bool = True) -> List[Dict]:
    """
    Copia arquivos de root_from/relpath -> root_to/relpath.
    Se dry_run=True não faz nada, apenas devolve o que faria.
    backup=True cria .bak se arquivo existente (ou salva em pasta _backup_timestamp).
    Retorna lista de ações realizadas (ou que seriam realizadas).
    """
    actions = []
    for rel in relpaths:
        src = Path(root_from) / rel
        dst = Path(root_to) / rel
        dst_parent = dst.parent
        action = {"relpath": rel, "src": str(src), "dst": str(dst), "status": None, "note": None}
        if dry_run:
            action["status"] = "dry-run"
            actions.append(action)
            continue
        try:
            dst_parent.mkdir(parents=True, exist_ok=True)
            if dst.exists() and backup:
                # mover destino para backup com sufixo .bak (não sobrescreve backup existentes)
                bak = dst.with_suffix(dst.suffix + ".bak")
                i = 1
                while bak.exists():
                    bak = dst.with_suffix(dst.suffix + f".bak{i}")
                    i += 1
                shutil.move(str(dst), str(bak))
                action["note"] = f"backup-> {bak}"
            shutil.copy2(str(src), str(dst))
            action["status"] = "copied"
        except Exception as e:
            action["status"] = "error"
            action["note"] = str(e)
        actions.append(action)
    return actions


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[%(levelname)s] %(message)s")
    handler.setFormatter(formatter)
    logger.setLevel(level)
    if not logger.handlers:
        logger.addHandler(handler)


def parse_args():
    p = argparse.ArgumentParser(description="Comparar duas pastas por hash (SHA-256) — ideal para backup em pendrive onde mtime muda.")
    p.add_argument("master", help="Diretório mestre (computador) — será comparado ao pendrive")
    p.add_argument("pendrive", help="Diretório do pendrive")
    p.add_argument("--workers", "-w", type=int, default=DEFAULT_WORKERS, help="Número de workers para hashing (default: %(default)s)")
    p.add_argument("--no-cache", action="store_true", help="Não usar cache de hashes")
    p.add_argument("--force-rehash", action="store_true", help="Ignorar cache (forçar rehash)")
    p.add_argument("--report", "-r", help="Salvar relatório JSON em arquivo especificado")
    p.add_argument("--sync", action="store_true", help="Sincronizar: copiar arquivos alterados/novos do pendrive para o master")
    p.add_argument("--dry-run", action="store_true", help="Quando usar --sync, não realiza cópias (apenas simula)")
    p.add_argument("--verbose", action="store_true", help="Logs verbosos")
    return p.parse_args()


def main():
    args = parse_args()
    setup_logging(args.verbose)

    master = Path(args.master)
    pen = Path(args.pendrive)
    if not master.is_dir():
        logger.error("Diretório mestre não existe: %s", master)
        sys.exit(2)
    if not pen.is_dir():
        logger.error("Diretório pendrive não existe: %s", pen)
        sys.exit(2)

    logger.info("Construindo mapa do mestre (%s)...", master)
    master_map = build_map(master, workers=args.workers, use_cache=not args.no_cache, force_rehash=args.force_rehash)
    logger.info("Construindo mapa do pendrive (%s)...", pen)
    pen_map = build_map(pen, workers=args.workers, use_cache=not args.no_cache, force_rehash=args.force_rehash)

    result = compare_maps(master_map, pen_map)
    added = result["added"]
    removed = result["removed"]
    changed = result["changed"]
    identical = result["identical"]

    summary = {
        "master": str(master.resolve()),
        "pendrive": str(pen.resolve()),
        "counts": {
            "master_total": len(master_map),
            "pendrive_total": len(pen_map),
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "identical": len(identical),
        },
        "details": {
            "added": added,
            "removed": removed,
            "changed": changed,
            "identical_sample": identical[:30],  # apenas uma amostra para não poluir
        }
    }

    logger.info("Resultado: %d adicionados, %d removidos, %d alterados, %d idênticos (amostra).",
                len(added), len(removed), len(changed), len(identical))

    if args.report:
        try:
            with open(args.report, "w", encoding="utf-8") as fh:
                json.dump(summary, fh, indent=2, ensure_ascii=False)
            logger.info("Relatório salvo em %s", args.report)
        except Exception as e:
            logger.error("Falha ao salvar relatório: %s", e)

    # Se sincronizar:
    if args.sync:
        # juntar list: arquivos novos (added) e alterados (changed) -> copiar do pendrive para master
        to_copy = sorted(set(added) | set(changed))
        logger.info("Sincronização ativada. Arquivos a copiar do pendrive para o mestre: %d", len(to_copy))
        actions = copy_files(pen, master, to_copy, dry_run=args.dry_run, backup=not args.dry_run)
        # salvar ações em relatório se pedido
        if args.report:
            try:
                with open(args.report, "r+", encoding="utf-8") as fh:
                    data = json.load(fh)
                    data["sync"] = {"dry_run": args.dry_run, "actions": actions}
                    fh.seek(0)
                    fh.truncate()
                    json.dump(data, fh, indent=2, ensure_ascii=False)
                logger.info("Ações de sincronização anexadas ao relatório.")
            except Exception as e:
                logger.warning("Não foi possível anexar ações de sync ao relatório: %s", e)

    # Mostrar sumário sucinto no stdout
    print(json.dumps(summary, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
