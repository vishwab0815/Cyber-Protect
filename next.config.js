/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: {
    serverActions: {
      bodySizeLimit: '2mb',
    },
  },
  turbopack: {}, // Enable Turbopack (Next.js 16 default)
  webpack: (config) => {
    config.resolve.alias.canvas = false;
    return config;
  },
}

module.exports = nextConfig
