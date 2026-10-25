import "./globals.css";
import "./console.css";

export const metadata = {
  title: "ARIS · Detection Ops Console",
  description: "SOC log triage platform with hybrid detection",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
