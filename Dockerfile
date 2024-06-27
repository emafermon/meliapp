# Use the Alpine Linux base image
FROM node:18-alpine AS base

# Set the working directory
WORKDIR /app

# Copy the package.json and package-lock.json files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy the source code
COPY src ./src
COPY tsconfig.json ./
COPY .eslintrc.json ./

# Run the linter
RUN npm run lint

# Build the TypeScript code
RUN npm run build

# Use a smaller runtime image
FROM node:18-alpine AS runtime

# Set the working directory
WORKDIR /app

# Copy the compiled JavaScript files from the build stage
COPY --from=base /app/dist ./dist

# Copy tnode_modules folder
COPY --from=base /app/node_modules ./node_modules

# Expose the port
EXPOSE 3000

# Start the application
CMD ["node", "dist/index.js"]
