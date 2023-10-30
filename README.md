# Transactions Microservice

Besides authentication you get transactions endpoints for working with transactions. Rest api is provided by express.js, and it runs on the port you specify like `env PORT=8000`, 8000 is the default port.

For each transaction endpoint you must provide `Authorization` header containing the access token from sign in endpoint.

## Installation

- Clone repository
- Run `docker compose -f "docker-composer.yml" up -d --build`
- Run `npm run start` ( You can run "Launch Program" from Visual Studio )


## Testing

You can rather run `npm run test` or use https://paw.cloud and open *requests.paw* to play with endpoints.

## Roadmap

[✔] - Registration/Authentication

[✔] - Simple transactions

[ ] - Wallet

[ ] - Complex transactions