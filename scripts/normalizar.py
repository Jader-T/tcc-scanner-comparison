#!/usr/bin/env python3
"""Normaliza os relatórios do Trivy, Grype e Clair de um artefato consolidado.
 
Uso:
    python3 normalizar.py <consolidado> [--saida normalizado] [--repeticao 1] [--rapido]
 
Entrada: diretório com tempos.csv, tamanhos.csv (opcional) e todos/NN/.
Saída: imagens.csv, tempos.csv, achados.csv, resumo.csv, determinismo.csv
e verificacao.txt.
Usa apenas a biblioteca padrão.
"""
 
import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
 
FERRAMENTAS = ("trivy", "grype", "clair")
VISOES = ("padrao", "normalizada", "completa")
SEVERIDADES = ("critica", "alta", "media", "baixa", "negligivel", "desconhecida")
PESO_SEVERIDADE = {s: i for i, s in enumerate(reversed(SEVERIDADES))}
 
MAPA_SEVERIDADE = {
    "critical": "critica",
    "high": "alta",
    "medium": "media",
    "moderate": "media",
    "low": "baixa",
    "negligible": "negligivel",
    "unknown": "desconhecida",
}
 
ECO_TRIVY = {
    "debian": "deb", "ubuntu": "deb",
    "alpine": "apk", "wolfi": "apk", "chainguard": "apk",
    "redhat": "rpm", "centos": "rpm", "rocky": "rpm", "alma": "rpm",
    "amazon": "rpm", "oracle": "rpm", "photon": "rpm", "suse": "rpm",
    "node-pkg": "npm", "npm": "npm", "yarn": "npm", "pnpm": "npm",
    "python-pkg": "pypi", "pip": "pypi", "pipenv": "pypi", "poetry": "pypi",
    "gobinary": "go", "gomod": "go",
    "jar": "maven", "pom": "maven", "gradle": "maven",
    "composer": "composer", "composer-vendor": "composer",
    "gemspec": "gem", "bundler": "gem",
    "rustbinary": "cargo", "cargo": "cargo",
    "nuget": "nuget", "dotnet-core": "nuget",
}
 
ECO_GRYPE = {
    "deb": "deb", "apk": "apk", "rpm": "rpm",
    "npm": "npm", "python": "pypi", "go-module": "go",
    "java-archive": "maven", "jenkins-plugin": "maven",
    "php-composer": "composer", "gem": "gem",
    "rust-crate": "cargo", "dotnet": "nuget",
    "binary": "binario",
}
 
ECO_OS = {"deb", "apk", "rpm"}
 
PACOTES_KERNEL = {"linux-libc-dev", "kernel-headers"}
 
RE_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
 
 
def severidade(valor):
    return MAPA_SEVERIDADE.get(str(valor or "").strip().lower(), "desconhecida")
 
 
def tipo_id(vid):
    m = re.match(r"([A-Za-z]+)-", vid)
    return m.group(1).upper() if m else "OUTRO"
 
 
def eh_kernel(pacote, fonte=""):
    p = (pacote or "").lower()
    return p in PACOTES_KERNEL or p.startswith("linux-headers-")
 
 
def camada(eco):
    return "os" if eco in ECO_OS else "aplicacao"
 
 
def ler_texto(caminho):
    try:
        return caminho.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
 
 
def ler_json(caminho):
    try:
        with open(caminho, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None
 
 
def novo_achado(vid, original, pacote, versao, fonte, eco, sev, correcao,
                ignorado=False):
    return {
        "id": vid,
        "id_original": original,
        "tipo_id": tipo_id(vid),
        "pacote": pacote or "",
        "versao": versao or "",
        "pacote_fonte": fonte or "",
        "ecossistema": eco,
        "camada": camada(eco),
        "severidade": sev,
        "correcao": "sim" if correcao else "nao",
        "kernel_headers": int(eh_kernel(pacote, fonte)),
        "ignorado": int(ignorado),
        "id_temporario": int(vid.upper().startswith("TEMP-")),
    }
 
 
def extrair_trivy(dados):
    achados, meta = [], {}
    if not dados:
        return achados, meta
    os_info = (dados.get("Metadata") or {}).get("OS") or {}
    meta["so"] = " ".join(x for x in (os_info.get("Family"), os_info.get("Name")) if x)
    meta["eosl_trivy"] = "sim" if os_info.get("EOSL") else "nao"
    for r in dados.get("Results") or []:
        tipo = (r.get("Type") or "").lower()
        if r.get("Class") == "os-pkgs":
            eco = ECO_TRIVY.get(tipo, "deb")
        else:
            eco = ECO_TRIVY.get(tipo, "outro")
            if eco in ECO_OS:
                eco = "outro"
        for v in r.get("Vulnerabilities") or []:
            vid = v.get("VulnerabilityID", "")
            achados.append(novo_achado(
                vid, vid, v.get("PkgName"), v.get("InstalledVersion"),
                v.get("SrcName", ""), eco, severidade(v.get("Severity")),
                bool(v.get("FixedVersion")),
            ))
    return achados, meta
 
 
def id_grype(m):
    vid = (m.get("vulnerability") or {}).get("id", "")
    if vid.startswith("CVE-"):
        return vid
    for rel in m.get("relatedVulnerabilities") or []:
        if str(rel.get("id", "")).startswith("CVE-"):
            return rel["id"]
    return vid
 
 
def achado_grype(m, ignorado):
    vul = m.get("vulnerability") or {}
    art = m.get("artifact") or {}
    ups = art.get("upstreams") or []
    fonte = ups[0].get("name", "") if ups else ""
    eco = ECO_GRYPE.get(art.get("type", ""), "outro")
    fix = vul.get("fix") or {}
    return novo_achado(
        id_grype(m), vul.get("id", ""), art.get("name"), art.get("version"),
        fonte, eco, severidade(vul.get("severity")),
        fix.get("state") == "fixed", ignorado,
    )
 
 
def extrair_grype(dados):
    achados, meta = [], {}
    if not dados:
        return achados, meta
    d = dados.get("distro") or {}
    meta["distro_grype"] = " ".join(x for x in (d.get("name"), d.get("version")) if x)
    for m in dados.get("matches") or []:
        achados.append(achado_grype(m, False))
    for m in dados.get("ignoredMatches") or []:
        achados.append(achado_grype(m, True))
    return achados, meta
 
 
def eco_clair(updater):
    u = (updater or "").lower()
    if u.startswith("osv/"):
        nome = u.split("/", 1)[1]
        return {"pypi": "pypi", "go": "go", "maven": "maven", "npm": "npm",
                "rubygems": "gem", "crates.io": "cargo", "nuget": "nuget",
                "packagist": "composer"}.get(nome, "outro")
    if u.startswith(("debian", "ubuntu")):
        return "deb"
    if u.startswith(("alpine", "wolfi", "chainguard")):
        return "apk"
    if u.startswith(("rhel", "rhcc", "oracle", "suse", "photon", "aws", "amazon")):
        return "rpm"
    return "outro"
 
 
def ids_clair(v):
    nome = v.get("name") or ""
    cves = RE_CVE.findall(nome) or RE_CVE.findall(v.get("links") or "")
    if cves:
        return list(dict.fromkeys(cves))
    return [nome or v.get("id", "")]
 
 
def extrair_clair(dados):
    achados, meta = [], {}
    if not dados:
        return achados, meta
    pacotes = dados.get("packages") or {}
    vulns = dados.get("vulnerabilities") or {}
    meta["clair_pacotes"] = len(pacotes)
    for pid, lista in (dados.get("package_vulnerabilities") or {}).items():
        pkg = pacotes.get(pid) or {}
        fonte = (pkg.get("source") or {}).get("name", "")
        for vid_interno in lista:
            v = vulns.get(vid_interno)
            if not v:
                continue
            eco = eco_clair(v.get("updater"))
            sev = severidade(v.get("normalized_severity"))
            for vid in ids_clair(v):
                achados.append(novo_achado(
                    vid, v.get("name", ""), pkg.get("name"), pkg.get("version"),
                    fonte, eco, sev, bool(v.get("fixed_in_version")),
                ))
    return achados, meta
 
 
EXTRATORES = {"trivy": extrair_trivy, "grype": extrair_grype, "clair": extrair_clair}
 
 
def deduplicar(achados):
    vistos, saida = set(), []
    for a in achados:
        chave = (a["id"], a["pacote"], a["versao"], a["ignorado"])
        if chave not in vistos:
            vistos.add(chave)
            saida.append(a)
    return saida
 
 
def filtrar(achados, visao):
    if visao == "padrao":
        return [a for a in achados if not a["ignorado"]]
    if visao == "normalizada":
        return [a for a in achados if not a["ignorado"] and not a["kernel_headers"]]
    return achados
 
 
def resumir(achados):
    """Conta IDs únicos; a severidade de um ID é a maior entre seus achados."""
    por_id = {}
    for a in achados:
        info = por_id.setdefault(a["id"], {"sev": a["severidade"], "camadas": set(),
                                           "correcao": False, "temp": a["id_temporario"]})
        if PESO_SEVERIDADE[a["severidade"]] > PESO_SEVERIDADE[info["sev"]]:
            info["sev"] = a["severidade"]
        info["camadas"].add(a["camada"])
        info["correcao"] |= a["correcao"] == "sim"
    linha = {
        "ids_unicos": len(por_id),
        "achados": len(achados),
        "pacotes_afetados": len({(a["pacote"], a["versao"]) for a in achados}),
    }
    for s in SEVERIDADES:
        linha[s] = sum(1 for i in por_id.values() if i["sev"] == s)
    linha["ids_os"] = sum(1 for i in por_id.values() if "os" in i["camadas"])
    linha["ids_aplicacao"] = sum(1 for i in por_id.values() if "aplicacao" in i["camadas"])
    linha["ids_com_correcao"] = sum(1 for i in por_id.values() if i["correcao"])
    linha["ids_temporarios"] = sum(1 for i in por_id.values() if i["temp"])
    return linha
 
 
def listar_imagens(base):
    todos = base / "todos"
    if not todos.is_dir():
        sys.exit(f"diretório não encontrado: {todos}")
    tamanhos = {}
    arq = base / "tamanhos.csv"
    if arq.exists():
        with open(arq, newline="", encoding="utf-8") as f:
            for r in csv.DictReader(f):
                tamanhos[r["imagem"]] = r["tamanho_bytes"]
    imagens = []
    for pasta in sorted(p for p in todos.iterdir() if p.is_dir()):
        nome = ler_texto(pasta / "nome.txt")
        if not nome:
            primeira = ler_texto(pasta / "tempos.csv").splitlines()
            nome = primeira[0].split(",")[0] if primeira else pasta.name
        tamanho = ler_texto(pasta / "tamanho_bytes.txt") or tamanhos.get(nome, "")
        imagens.append({"ordem": int(pasta.name) if pasta.name.isdigit() else len(imagens) + 1,
                        "pasta": pasta, "imagem": nome, "tamanho_bytes": tamanho})
    return imagens
 
 
def repeticoes(pasta, ferramenta):
    reps = []
    for arq in pasta.glob(f"{ferramenta}_r*.json"):
        m = re.match(rf"{ferramenta}_r(\d+)\.json$", arq.name)
        if m:
            reps.append(int(m.group(1)))
    return sorted(reps)
 
 
def ler_tempos(base, imagens):
    linhas = []
    arq = base / "tempos.csv"
    if arq.exists():
        with open(arq, newline="", encoding="utf-8") as f:
            linhas = list(csv.DictReader(f))
    else:
        cab = ["imagem", "ferramenta", "repeticao", "condicao", "tempo_ms", "codigo_saida"]
        for img in imagens:
            for linha in ler_texto(img["pasta"] / "tempos.csv").splitlines():
                if linha.strip():
                    linhas.append(dict(zip(cab, linha.split(","))))
    return linhas
 
 
def mb(valor):
    try:
        return round(int(valor) / 1_000_000, 1)
    except (TypeError, ValueError):
        return ""
 
 
def escrever_csv(caminho, campos, linhas):
    with open(caminho, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos, extrasaction="ignore")
        w.writeheader()
        w.writerows(linhas)
 
 
def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("consolidado", type=Path)
    ap.add_argument("--saida", type=Path, default=None)
    ap.add_argument("--repeticao", type=int, default=1,
                    help="repetição usada para os achados (padrão: 1)")
    ap.add_argument("--rapido", action="store_true",
                    help="não compara as demais repetições")
    args = ap.parse_args()
 
    base = args.consolidado
    saida = args.saida or base / "normalizado"
    saida.mkdir(parents=True, exist_ok=True)
 
    imagens = listar_imagens(base)
    ordem = {i["imagem"]: i["ordem"] for i in imagens}
    tamanho = {i["imagem"]: i["tamanho_bytes"] for i in imagens}
 
    avisos, vazios = [], []
    tabela_imagens, todos_achados, resumo, determinismo = [], [], [], []
 
    for img in imagens:
        nome, pasta = img["imagem"], img["pasta"]
        print(f"[{img['ordem']:02d}] {nome}", file=sys.stderr)
        meta_img = {"ordem": img["ordem"], "imagem": nome,
                    "tamanho_bytes": img["tamanho_bytes"], "tamanho_mb": mb(img["tamanho_bytes"])}
 
        for ferr in FERRAMENTAS:
            arq = pasta / f"{ferr}_r{args.repeticao}.json"
            dados = ler_json(arq)
            if dados is None:
                avisos.append(f"{nome}: {arq.name} ausente ou inválido")
            achados, meta = EXTRATORES[ferr](dados)
            achados = deduplicar(achados)
            meta_img.update(meta)
 
            for a in achados:
                todos_achados.append({"ordem": img["ordem"], "imagem": nome,
                                      "ferramenta": ferr, "repeticao": args.repeticao, **a})
            for visao in VISOES:
                linha = resumir(filtrar(achados, visao))
                resumo.append({"ordem": img["ordem"], "imagem": nome,
                               "ferramenta": ferr, "visao": visao, **linha})
 
            ids_ref = {a["id"] for a in filtrar(achados, "padrao")}
            if dados is not None and not ids_ref:
                vazios.append(f"{nome}: {ferr}")
 
            if args.rapido:
                continue
            for rep in repeticoes(pasta, ferr):
                if rep == args.repeticao:
                    continue
                outros, _ = EXTRATORES[ferr](ler_json(pasta / f"{ferr}_r{rep}.json"))
                ids = {a["id"] for a in filtrar(deduplicar(outros), "padrao")}
                determinismo.append({
                    "imagem": nome, "ferramenta": ferr, "repeticao": rep,
                    "ids_ref": len(ids_ref), "ids": len(ids),
                    "so_ref": len(ids_ref - ids), "so_rep": len(ids - ids_ref),
                })
 
        txt = ler_texto(pasta / f"clair_r{args.repeticao}.txt")
        m = re.search(r"pacotes=(\d+)", txt)
        if m and int(m.group(1)) == 0:
            avisos.append(f"{nome}: Clair indexou 0 pacotes")
        tabela_imagens.append(meta_img)
 
    escrever_csv(saida / "imagens.csv",
                 ["ordem", "imagem", "tamanho_bytes", "tamanho_mb", "so",
                  "eosl_trivy", "distro_grype", "clair_pacotes"],
                 tabela_imagens)
 
    tempos = []
    for t in ler_tempos(base, imagens):
        try:
            ms = int(t["tempo_ms"])
        except (KeyError, ValueError):
            avisos.append(f"tempo inválido: {t}")
            continue
        if str(t.get("codigo_saida", "0")) != "0":
            avisos.append(f"{t['imagem']}: {t['ferramenta']} r{t['repeticao']} "
                          f"terminou com código {t['codigo_saida']}")
        tempos.append({
            "ordem": ordem.get(t["imagem"], ""), "imagem": t["imagem"],
            "ferramenta": t["ferramenta"], "repeticao": t["repeticao"],
            "condicao": t["condicao"], "tempo_ms": ms, "tempo_s": round(ms / 1000, 3),
            "codigo_saida": t["codigo_saida"],
            "tamanho_bytes": tamanho.get(t["imagem"], ""),
            "tamanho_mb": mb(tamanho.get(t["imagem"], "")),
        })
    escrever_csv(saida / "tempos.csv",
                 ["ordem", "imagem", "ferramenta", "repeticao", "condicao", "tempo_ms",
                  "tempo_s", "codigo_saida", "tamanho_bytes", "tamanho_mb"],
                 tempos)
 
    escrever_csv(saida / "achados.csv",
                 ["ordem", "imagem", "ferramenta", "repeticao", "id", "id_original",
                  "tipo_id", "pacote", "versao", "pacote_fonte", "ecossistema", "camada",
                  "severidade", "correcao", "kernel_headers", "ignorado", "id_temporario"],
                 todos_achados)
 
    escrever_csv(saida / "resumo.csv",
                 ["ordem", "imagem", "ferramenta", "visao", "ids_unicos", "achados",
                  "pacotes_afetados", *SEVERIDADES, "ids_os", "ids_aplicacao",
                  "ids_com_correcao", "ids_temporarios"],
                 resumo)
 
    if determinismo:
        escrever_csv(saida / "determinismo.csv",
                     ["imagem", "ferramenta", "repeticao", "ids_ref", "ids", "so_ref", "so_rep"],
                     determinismo)
 
    with open(saida / "verificacao.txt", "w", encoding="utf-8") as f:
        reps_esperadas = {t["repeticao"] for t in tempos}
        f.write(f"consolidado: {base.resolve()}\n")
        f.write(f"imagens: {len(imagens)}\n")
        f.write(f"medições de tempo: {len(tempos)} (repetições: {', '.join(sorted(reps_esperadas))})\n")
        f.write(f"achados (repetição {args.repeticao}): {len(todos_achados)}\n\n")
 
        f.write("Avisos\n")
        f.write("".join(f"  - {a}\n" for a in avisos) or "  nenhum\n")
 
        f.write(f"\nRelatórios sem vulnerabilidades (repetição {args.repeticao})\n")
        f.write("".join(f"  - {v}\n" for v in vazios) or "  nenhum\n")
 
        f.write("\nDeterminismo (IDs da visão padrão comparados à repetição de referência)\n")
        if args.rapido:
            f.write("  não verificado (--rapido)\n")
        elif not determinismo:
            f.write("  apenas uma repetição disponível\n")
        else:
            diferentes = [d for d in determinismo if d["so_ref"] or d["so_rep"]]
            f.write(f"  comparações: {len(determinismo)}; com diferença: {len(diferentes)}\n")
            for d in diferentes:
                f.write(f"  - {d['imagem']} {d['ferramenta']} r{d['repeticao']}: "
                        f"{d['ids']} IDs (ref {d['ids_ref']}), "
                        f"-{d['so_ref']} +{d['so_rep']}\n")
 
        f.write("\nIDs únicos por imagem (padrão | normalizada | completa)\n")
        idx = {(r["imagem"], r["ferramenta"], r["visao"]): r["ids_unicos"] for r in resumo}
        largura = max(len(i["imagem"]) for i in imagens) if imagens else 10
        f.write(f"  {'imagem':<{largura}}  " +
                "  ".join(f"{x:>20}" for x in FERRAMENTAS) + "\n")
        for img in imagens:
            cols = []
            for ferr in FERRAMENTAS:
                v = [idx[(img["imagem"], ferr, vis)] for vis in VISOES]
                cols.append(f"{v[0]:>6} {v[1]:>6} {v[2]:>6}")
            f.write(f"  {img['imagem']:<{largura}}  " + "  ".join(cols) + "\n")
 
    print(f"saída em {saida}", file=sys.stderr)
    if avisos:
        print(f"{len(avisos)} aviso(s), veja verificacao.txt", file=sys.stderr)
 
 
if __name__ == "__main__":
    main()
