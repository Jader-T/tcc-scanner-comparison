"""Executado dentro da imagem: lista os componentes dos três blocos (TSV)."""
import glob
import importlib.metadata as md
import json
import zipfile

print("bloco\tecossistema\tpacote\tversao\tcaminho")
for d in sorted(md.distributions(), key=lambda d: d.metadata["Name"].lower()):
    print(f"pip\tPyPI\t{d.metadata['Name']}\t{d.version}\t{d.locate_file('')}")
pacotes = glob.glob("/opt/app/node_modules/*/package.json") + \
    glob.glob("/opt/app/node_modules/@*/*/package.json")
for f in sorted(pacotes):
    p = json.load(open(f))
    print(f"npm\tnpm\t{p['name']}\t{p['version']}\t{f}")
for jar in sorted(glob.glob("/opt/legado/*.jar")):
    with zipfile.ZipFile(jar) as z:
        for n in z.namelist():
            if n.startswith("META-INF/maven/") and n.endswith("pom.properties"):
                props = dict(l.split("=", 1) for l in z.read(n).decode().splitlines()
                             if "=" in l and not l.startswith("#"))
                print(f"jar\tMaven\t{props['groupId']}:{props['artifactId']}\t{props['version']}\t{jar}")
