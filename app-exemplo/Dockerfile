# Aplicação de exemplo do security gate.
# Troque os dois FROM pela imagem fixada por digest (node:22-alpine@sha256:...).

FROM node@sha256:0e1754758c2df4cfa3e68d59e2e1b7374bb7fd9ea6328eaaacf15cc934af8202 AS dependencias
LABEL org.opencontainers.image.source="https://github.com/jader-t/tcc-scanner-comparison" \
      org.opencontainers.image.description="Aplicação de exemplo do security gate do TCC"
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts

FROM dependencias AS teste
COPY index.js ./
COPY test ./test
RUN node --test

FROM node:22-alpine
# Aplica as correções de segurança do Alpine e remove os gerenciadores de
# pacotes do Node, que não são usados em execução.
   RUN apk upgrade --no-cache && \
       rm -rf /usr/local/lib/node_modules /usr/local/bin/npm /usr/local/bin/npx \
              /usr/local/bin/corepack /opt/yarn-* /usr/local/bin/yarn /usr/local/bin/yarnpkg
WORKDIR /app
COPY --from=dependencias /app/node_modules ./node_modules
COPY package.json index.js ./
USER node
CMD ["node", "index.js"]
