import type { Metadata } from "next"
import "./globals.css"

export const metadata: Metadata = {
  title: "ProxyPulse · 代理节点监测",
  description: "本地运行的个人代理节点延迟与 Timeout 监测面板。",
  icons: { icon: "/favicon.svg", shortcut: "/favicon.svg" },
}

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="zh-CN"><body>{children}</body></html>
}
