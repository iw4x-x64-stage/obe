# libobe - Demonware protocol library for IW4x projects and infrastructure.

The `libobe` C++ library implements Demonware protocol as IW4x speaks
it: authentication tickets, the lobby service gateway framing and
encryption, the bit and byte buffers, and the services behind the
gateway.

## Usage

To start using `libobe` in your project, add the following `depends`
value to your `manifest`, adjusting the version constraint as appropriate:

```
depends: libobe ^0.1.0
```

Then import the library in your `buildfile`:

```
import libs = libobe%lib{obe}
```
