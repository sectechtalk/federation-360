# Federation 360 container image.
#   dev   : Vite dev server with hot reload (source is bind-mounted by docker-compose.yml)
#   build : runs the tests and the production build
#   serve : the built single-file dashboard on nginx (closest to what ships)

FROM node:22-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
# The shared tenant collector (@sectechtalk/f360-collector) is a vendored package file, so the
# build needs no GitHub token and no package registry beyond npm's public one.
COPY vendor ./vendor
RUN npm ci

FROM deps AS dev
ENV F360_DOCKER=1
EXPOSE 5173
# docker-compose keeps node_modules in a named volume that outlives image rebuilds. When
# package.json gains or changes a dependency (for example a new collector version), reinstall
# into that volume first instead of failing on a missing module.
CMD ["sh", "-c", "npm ls --depth=0 >/dev/null 2>&1 || npm ci --no-audit --no-fund; exec npm run dev -- --host 0.0.0.0 --port 5173 --strictPort"]

FROM deps AS build
COPY . .
RUN npm test && npm run build

FROM nginx:1.27-alpine AS serve
COPY --from=build /app/dist/ /usr/share/nginx/html/
EXPOSE 80
