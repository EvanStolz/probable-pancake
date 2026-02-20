# CRX Security Checker

A web application to analyze Chrome extension permissions and categorize them by risk level (Low, Medium, High, Critical).

## Features

- Upload `.crx` or `.zip` extension files.
- Local analysis (no data leaves your browser).
- Detailed permission mapping with risk levels.
- Modern, responsive UI.

## Risk Levels

- **Critical**: Full access to all websites, system-level communication, or powerful debugging capabilities.
- **High**: Access to sensitive data like cookies, history, or specific website data.
- **Medium**: Access to browser features like storage, notifications, or geolocation.
- **Low**: Basic extension features like alarms, context menus, or UI elements.

## Tech Stack

- [Next.js](https://nextjs.org/)
- [Tailwind CSS](https://tailwindcss.com/)
- [Lucide React](https://lucide.dev/)
- [JSZip](https://stuk.github.io/jszip/)

## Getting Started

1. Install dependencies:
   ```bash
   npm install
   ```

2. Run the development server:
   ```bash
   npm run dev
   ```

3. Open [http://localhost:3000](http://localhost:3000) in your browser.
