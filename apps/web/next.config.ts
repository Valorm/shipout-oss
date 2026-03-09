import type { NextConfig } from 'next';

// Startup check for critical environment variables (non-fatal warning for Vercel deployments)
if (process.env.NODE_ENV === 'production') {
  if (!process.env.ENCRYPTION_KEY) {
    console.warn('[Config] WARNING: ENCRYPTION_KEY environment variable is not set. Service identity signing will use fallback.');
  } else if (Buffer.from(process.env.ENCRYPTION_KEY, 'hex').length !== 32) {
    console.warn('[Config] WARNING: ENCRYPTION_KEY must be a 32-byte hex string. Service identity signing may fail.');
  }
}

const nextConfig: NextConfig = {
  reactStrictMode: true,
  eslint: {
    ignoreDuringBuilds: false,
  },
  typescript: {
    ignoreBuildErrors: false,
  },
  images: {
    remotePatterns: [
      {
        protocol: 'https',
        hostname: 'picsum.photos',
        port: '',
        pathname: '/**',
      },
      {
        // FIX: GitHub user avatars used for authenticated user profile pictures
        protocol: 'https',
        hostname: 'avatars.githubusercontent.com',
        port: '',
        pathname: '/**',
      },
    ],
  },
  output: 'standalone',
  transpilePackages: ['motion'],
  webpack: (config, { dev }) => {
    if (dev && process.env.DISABLE_HMR === 'true') {
      config.watchOptions = {
        ignored: /.*/,
      };
    }
    return config;
  },
};

export default nextConfig;
