# Emergency Response Demo

Relay is a simulated emergency request and ambulance dispatch demo. It uses a Node.js/Express server, PostgreSQL persistence, server-side staff authentication, and role-based API authorization. It is not connected to emergency services and must not be used for real dispatch.

## Roles

- **Admin:** all screens and operational actions.
- **Dispatcher:** requests, ambulance assignments, drivers, and reports.
- **Ambulance Driver:** only the driver's own assigned calls and status updates.
- **Requester:** public request form without signing in; request records are scoped to that browser session.

Staff passwords are stored as bcrypt hashes. The browser never contains demo passwords or decides staff authorization.

## Run locally

Requirements: Node.js 20+ and a PostgreSQL database.

1. Install dependencies with `npm install`.
2. Copy `.env.example` to `.env`.
3. Set `DATABASE_URL`, a random `SESSION_SECRET` of at least 32 characters, and unique passwords of at least 12 characters for each `INITIAL_*_PASSWORD`.
4. Start the server with `npm start`, then open `http://localhost:3000`.

The first startup creates the schema and sample fleet, driver, and request records. Initial staff IDs are `ADM-1001`, `DSP-1001`, and `DRV-1001`; their passwords are the values configured in the corresponding environment variables. Initial passwords are only used when those staff records are first created.

Run the focused checks with `npm test`.

## Deploy to Render

The `render.yaml` Blueprint defines a free web service and free PostgreSQL database. Push this project to a GitHub repository named `emergency-response`, then create a new Blueprint from that repository in Render. Render generates `SESSION_SECRET` and unique initial staff passwords, and connects the database automatically. Save the generated staff passwords securely from the web service's Environment settings; they are used only when the staff records are first created.

Free hosting is intended for demonstration and may sleep or have database limits/expiration. Back up or export any data you need to keep. Use managed, monitored infrastructure and a security review before any real-world deployment.
