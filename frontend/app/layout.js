import "./globals.css";

export const metadata = {
  title: "ARIS - Automated Registry and Incident Sifting",
  description: "SOC log triage platform with hybrid detection",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
