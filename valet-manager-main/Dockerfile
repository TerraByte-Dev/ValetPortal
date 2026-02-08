# ---- Dockerfile (replace your current one) ----
FROM node:18-bullseye

WORKDIR /app

# Only copy manifests first for better layer caching
COPY package*.json ./

# Install prod deps only (no native rebuilds)
RUN npm ci --omit=dev

# Now copy the rest of the app
COPY . .

# Helpful envs (Railway will inject DATABASE_URL / SESSION_SECRET)
ENV NODE_ENV=production
ENV PORT=3000

EXPOSE 3000

# Start the server
CMD ["node", "server.js"]
