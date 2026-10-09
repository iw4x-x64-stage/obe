# libobe-apache - Apache status dashboard for IW4x projects and infrastructure.

The `libobe-apache` package builds `mod_obe`, an Apache module that
presents the state of an `obe` server as a status dashboard. It reads the
PostgreSQL database that `obe` writes.

## Usage

To start using `libobe-apache` in your project, add the following
`depends` value to your `manifest`, adjusting the version constraint as
appropriate:

```
depends: libobe-apache ^0.1.0
```

Then import the library in your `buildfile`:

```
import libs = libobe-apache%lib{obe-apache}
```
