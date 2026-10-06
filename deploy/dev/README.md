# Local development stack

Postgres 16, Ory Hydra v2.2 and a dev-mode Vault for running the backend locally.
None of this is for production.

```sh
make dev-up      # start Postgres (127.0.0.1:55433), Hydra (4444/4445), Vault (8200)
make run         # run the backend with deploy/dev/dev.env (migrations run at startup)
make dev-down    # stop the stack (data kept in the pgdata volume)
```

- **UI:** in `Authsec-ui`, set `VITE_API_URL=http://localhost:7468` and run `npm run dev` on port 5173. That port matches `WEBAUTHN_ORIGIN` and CORS in `dev.env`.
- **Email:** without SMTP, OTPs are printed in the backend log. This only happens because `ENVIRONMENT=development`.
- **Tests:** `make test` runs the unit tests. `make test-integration` runs the integration suites; they start their own Postgres through testcontainers and need Docker.
