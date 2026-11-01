# Imagem de referência do TCC: dependências deliberadamente vulneráveis.
# Não usar em produção.

FROM node@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS npm
WORKDIR /build
COPY npm/package.json npm/package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts \
 && rm -f node_modules/.package-lock.json

FROM python@sha256:2d97f6910b16bd338d3060f261f53f144965f755599aab1acda1e13cf1731b1b

LABEL org.opencontainers.image.title="tcc-referencia" \
      org.opencontainers.image.description="Imagem com vulnerabilidades para avaliação de scanners SCA. Não usar em prod"

# Bloco 1: Python via pip, sem dependências transitivas.
# pip, setuptools e wheel são removidos para que o ecossistema Python
# contenha apenas os pacotes do experimento.
COPY pip/requirements.txt /opt/app/requirements.txt
RUN pip install --no-cache-dir --no-deps -r /opt/app/requirements.txt \
 && python3 -m pip uninstall -y setuptools wheel pip

# node.js via npm (apenas node_modules, sem o runtime do Node).
COPY --from=npm /build/node_modules /opt/app/node_modules

# JAR copiado direto para o sistema de arquivos.
ADD https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar /opt/legado/
ADD https://repo1.maven.org/maven2/org/apache/logging/log4j/log4j-core/2.14.1/log4j-core-2.14.1.jar.sha1 /tmp/
RUN echo "$(cut -c1-40 /tmp/log4j-core-2.14.1.jar.sha1)  /opt/legado/log4j-core-2.14.1.jar" | sha1sum -c - \
 && rm /tmp/log4j-core-2.14.1.jar.sha1

CMD ["python3", "-c", "print('imagem de referencia do TCC')"]
