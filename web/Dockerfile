# Interception console. Build context is the repo root (compose.yaml), because the Corpus view
# bundles the human-owned eval corpus at build time.
# Stage 1 runs typecheck, lint, tests and the build: the image cannot exist if any of them fail.
# node:slim, not alpine: the lockfile is generated on Windows, and slim (glibc) resolves the
# native optional packages (rollup, lightningcss, tailwind oxide) reliably.
FROM node:24-slim AS build
WORKDIR /app/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --include=optional --no-audit --no-fund
COPY eval/corpus /app/eval/corpus
COPY web/ ./
RUN npm run check

FROM nginxinc/nginx-unprivileged:1.27-alpine AS runtime
COPY web/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/web/dist /usr/share/nginx/html
EXPOSE 8080
