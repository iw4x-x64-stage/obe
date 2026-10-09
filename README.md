# obe - Demonware online services server for IW4x.

`obe` serves Demonware online services that IW4x connects to:
authentication, the lobby service gateway, and the services behind it
(matchmaking, messaging, storage, performance reporting, and the
bandwidth test). Its state lives in PostgreSQL.

The protocol follows the x64 edition of the game client. The repository
holds two packages:

* [`obe`](obe/README.md): the server executable.
* [`libobe`](libobe/README.md): the protocol and service library.

Documentation: https://iw4x.io/projects/obe/doc/

## Usage

See the package `README.md` files listed above.

## Development

The development setup uses the standard `bdep`-based workflow and needs a
C++26 compiler (GCC 16 or later) and PostgreSQL. For example:

```
git clone https://github.com/iw4x-x64-stage/obe.git
cd obe

bdep init -C @gcc cc config.cxx=g++ config.cc.compiledb=./
bdep update
bdep test
```

The `config.cc.compiledb` value makes the build maintain
`compile_commands.json` in the repository root, which `.clangd` points
`clangd` to.

## Contributing

See https://github.com/iw4x/.github/blob/main/CONTRIBUTING.md

## License

obe is licensed under the GNU General Public License, version 3, subject
to the additional permissions described in version 1.1 of the IW4x
Linking Exception.

See LICENSE.md, LICENSE-EXCEPTION.md, and AUTHORS.
