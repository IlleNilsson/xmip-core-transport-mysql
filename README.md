# xmip-core-transport-mysql

MySQL transport: one row of a query is one Stream, a send is one INSERT. A
technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport). A
transport only: MySQL is never a Xmip Storage server.

MySQL and MariaDB speak one client/server protocol, and it is
[xmip-core-library-mariadb](https://github.com/IlleNilsson/xmip-core-library-mariadb)'s.
What is MySQL's own is this crate's, so that whatever Oracle changes in MySQL
lands here and nowhere else: the login.

## The login

`caching_sha2_password`, MySQL's default since 8.0 and, since 9.0 removed
`mysql_native_password` (8.4 had it off unless the server was started with
it), its only password plugin:

- **Fast**: the first answer is `SHA256(password) XOR
  SHA256(SHA256(SHA256(password)) + nonce)`; a server whose cache holds the
  account checks it and the login is done.
- **Full**: a server whose cache does not hold the account — the first login
  after it started — asks for the password itself. With `tls = true` it goes
  inside the estate's TLS (`xmip-core-library-tls`, ADR-0033) as it is. In the
  clear the client asks for the server's RSA public key and sends the password,
  masked with the nonce, encrypted to it with OAEP over SHA-1, as MySQL pads.
  A key asked for in the clear can be swapped by whoever can read the wire;
  `tls = true` is the answer to that.

A server that still switches an account to `mysql_native_password` is answered
in it, the library's.

## Settings

As the MariaDB transport's: `database`, `user` (the password the secret
the Location names), `query`, `accept`, `column`, `encoding`, `timeout`,
`tls` and `tls_name`. The SQL is `sql::MARIADB` from `xmip-core-library-sql`,
which MySQL reads the same: backtick identifiers, backslash escapes, the
`X'…'` literal. A binary column's receive query spells a BLOB out:
`SELECT id, CONCAT('0x', HEX(payload)) FROM inbox`.

The origin URI is `mysql://server/<database>?row=<name>`; a send target is
`mysql://host:3306/<database>/<table>/<column>`,
`host:3306/<database>/<table>/<column>` or `<table>/<column>`. A row is
consumed by the `accept` statement after its cycle, as for every SQL
transport (`transport::sql::accept`).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
