import "./globals.css";

import type { ReactNode } from "react";
import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "PDF Knowledge Base",
  description: "Text chat with streaming answers and TTS over PDF chunks.",
};

export default function RootLayout({
  children,
}: {
  children: ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
