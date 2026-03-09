import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'shipout',
  description: 'Security audit tool',
  icons: {
    icon: '/favicon.svg',
  },
};

import { headers } from 'next/headers';

export default async function RootLayout({ children }: { children: React.ReactNode }) {
  const nonce = (await headers()).get('x-nonce') || '';

  return (
    <html lang="en" className="dark">
      <body
        className="bg-[#0f0f11] poly-bg-texture text-zinc-100 font-sans antialiased"
        suppressHydrationWarning
      >
        {children}
      </body>
    </html>
  );
}
