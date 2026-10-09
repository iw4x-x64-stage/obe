# obe - Demonware online services server for IW4x.

The `obe` executable serves Demonware online services that IW4x connects
to. It answers the authentication requests over HTTPS, accepts the lobby
service gateway connections, exchanges the bandwidth test packets over
UDP, and keeps its state in PostgreSQL.

## Usage

Run `obe --help` for the list of options.
