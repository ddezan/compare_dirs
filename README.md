# 🧩 compare_dirs.py

**Comparador de diretórios via hash (SHA-256)** — compara duas pastas (ex: computador vs pen drive) identificando arquivos **adicionados, removidos, alterados e idênticos**, independentemente da data de modificação.

Ideal para **backups**, **sincronizações manuais** e **verificações de integridade** em grandes estruturas de arquivos.

---

## ⚙️ Funcionalidades

- Compara diretórios usando **hash SHA-256** (evita falsos positivos de modificação por datas diferentes).  
- **Suporte a caminhos longos** no Windows (`\\?\\` prefix).  
- Exibe **barra de progresso** durante o hashing (via `tqdm`).  
- **Cache automático de hashes** (`.hash_cache.json`) para acelerar execuções futuras.  
- **Paralelização** automática — utiliza múltiplos núcleos da CPU.  
- **Resiliente** a erros de permissão, nomes com encoding incorreto ou caminhos inacessíveis.  
- **Gera logs detalhados** tanto no terminal quanto em um arquivo `.log`.  

---

## 🧮 Requisitos

- Python **3.8+**
- Pacotes:
  ```bash
  pip install tqdm
  ```

---

## 🚀 Uso

### 1. Executar o script

```bash
python compare_dirs.py "C:\Backup\Mestre" "E:\Pendrive" -r resultado.json
```

### 2. Argumentos disponíveis

| Argumento | Descrição |
|------------|-----------|
| `master` | Caminho do diretório mestre (ex: computador). |
| `pendrive` | Caminho do diretório de comparação (ex: pen drive). |
| `-w`, `--workers` | Número de processos simultâneos (por padrão, usa todos menos 1). |
| `--no-cache` | Desativa o uso do cache de hashes. |
| `--force-rehash` | Ignora o cache e recalcula todos os hashes. |
| `-r`, `--report` | Gera um arquivo JSON com o resultado. |
| `--verbose` | Exibe logs detalhados. |

---

## 📊 Exemplo de saída

Na tela (e no arquivo de log):

```
[INFO] Listando arquivos em C:\Backup\Mestre ...
[INFO] Arquivos encontrados: 4532
Hashing Mestre: 100%|████████████████████| 4532/4532 [03:42<00:00, 20.32arq/s]
[INFO] Listando arquivos em E:\Pendrive ...
[INFO] Arquivos encontrados: 4525
Hashing Pendrive: 100%|██████████████████| 4525/4525 [03:10<00:00, 23.82arq/s]

{
  "added": ["nova_pasta/novo_arquivo.txt"],
  "removed": ["antigo/arquivo_obsoleto.docx"],
  "changed": ["planilhas/vendas.xlsx"],
  "identical_count": 4519
}

[INFO] Relatório salvo em resultado.json
[INFO] Log salvo em compare_dirs.log
```

---

## 🗂️ Estrutura de saída

O arquivo JSON (`--report`) contém:

```json
{
  "added": ["..."],      // Arquivos que existem apenas no pendrive
  "removed": ["..."],    // Arquivos que existem apenas no mestre
  "changed": ["..."],    // Arquivos com mesmo nome mas conteúdo diferente
  "identical_count": 4519 // Total de arquivos idênticos
}
```

---

## 🧵 Logs

- Todos os logs são salvos automaticamente no arquivo `compare_dirs.log`, localizado no mesmo diretório do script.  
- Os logs incluem mensagens `INFO`, `WARNING` e `ERROR` geradas durante o processo.

---

## 💡 Dicas de uso

- Execute com `--verbose` para detalhes completos (útil na primeira execução).  
- Utilize o cache padrão para evitar reprocessar arquivos inalterados.  
- Caso suspeite de modificações em massa, use `--force-rehash`.  
- Pode ser integrado em rotinas de backup (ex: `PowerShell`, `cron`, etc.).  

---

## 🤪 Exemplo prático

Comparar o conteúdo do computador com o pendrive e gerar relatório detalhado:

```bash
python compare_dirs.py "D:\Projetos" "F:\BackupPendrive" --verbose -r comparativo.json
```

---

## 📜 Licença

Este projeto é distribuído sob a licença **MIT**, permitindo uso, modificação e distribuição livre, desde que mantidos os créditos originais.

---

## 👨‍🔧 Autor

**Daniel Dezan Lopes da Silva**  
🕊️ Projeto criado para facilitar comparações precisas de backup entre dispositivos.

---