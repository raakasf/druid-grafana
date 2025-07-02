# Getting started

A data source backend plugin consists of both frontend (TypeScript) and backend (Golang) components. A TypeScript development environment and a Golang one are needed in order to work over that plugin.
For more technical information about backend plugins, refer to the documentation on [Backend plugins](https://grafana.com/developers/plugin-tools/key-concepts/backend-plugins/).

## Development environment

The unified development environment is built atop Docker containers, composed with Docker Compose v2. It provides a running Druid instance, a running Grafana instance (use druid/druid as username/password to login), and a toolbox container for building.

### Prerequisites
- Docker with Compose v2 (use `docker compose` command)
- The project automatically uses Docker Compose v2 syntax

Any building is done within the `toolbox` container which includes:
- Node.js 20 with latest npm
- Go compiler
- Git and other build tools

This saves you from setting up Node and Golang development environments on your host.

Mage (See https://magefile.org) is used to run commands over the environment (mostly within the `toolbox` container).

_If you don't want to run commands in the development environment container, you can set the environment variable `GRAFADRUID_USE_DOCKER=0` and the commands will be run against your host._

In the same "plug & play" spirit, Mage is provided as a binary so you don't have to install it locally.

- To start the environment, run: `./mage env:start`
- To stop the environment, run: `./mage env:stop`

Once the env is started (with `./mage env:start`) you can build plugin parts or the whole plugin:

- To build frontend part of the plugin, run `./mage frontend:build`
- To build backend part of the plugin, run `./mage backend:build`
- To build the whole plugin, run `./mage buildAll` (or simply, `./mage`)

Few more targets are available (tests, cleanup, ...), you can list them all with `./mage -l`.

### Development Tips

- If you update `Magefile.go`, use `./mage env:updateMage` to update the mage binary
- The `sdk:*` targets (provided by Grafana backend plugin SDK) run within the container via the `backend:*` targets
- Use `./mage -l` to list all available targets
- Environment variables are configured in the `.env` file at the project root
