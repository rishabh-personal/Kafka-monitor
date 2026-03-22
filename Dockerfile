FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY package.json ./
RUN npm install --omit=dev

# Copy source
COPY . .

# DigitalOcean injects PORT automatically
EXPOSE 3000

CMD ["node", "index.js"]
