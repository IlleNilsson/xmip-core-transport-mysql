#![forbid(unsafe_code)]

//! Streams that arrive as rows of a MySQL server. One row is one Stream:
//! the last column of a configured query is what Xmip carries, the first
//! column is where it came from. A transport only: MySQL is never a Xmip
//! Storage server, and nothing that starts a node names it.
//!
//! MySQL and `MariaDB` speak one protocol, and it is
//! `xmip-core-library-mariadb`'s: the packets, the greeting, the result set,
//! the client and the far end. What is MySQL's own is this crate's, so that
//! whatever Oracle changes in MySQL lands here and nowhere else (the owner,
//! 2026-10-14: *One never knows what Oracle does or do not*): the login.
//! MySQL logs in with `caching_sha2_password` (`caching_sha2_password.rs`),
//! its default since 8.0 and its only password plugin since 9.0; a server
//! that still switches an account to `mysql_native_password` (8.0, or 8.4
//! started with it) is answered in that, the library's. The full
//! authentication — the password itself, which a server whose cache does
//! not hold the account asks for — goes over the estate's TLS where
//! `tls = true`, and encrypted to the server's RSA key otherwise.
//!
//! A Receive Location runs its query — `SELECT id, payload FROM inbox
//! ORDER BY id` unless told otherwise — and hands each row up; a Send
//! Location inserts the Stream as one column of one row. What the column
//! holds is the Location's to declare (ADR-0038), as for every SQL
//! transport (`transport::sql`): `column = "binary"`, the default, inserts
//! an `X'…'` literal and reads a value back from a hex form; `column =
//! "text"` decodes the Stream strictly in its `encoding`. The SQL is the
//! `MariaDB` dialect of `xmip-core-library-sql`, which MySQL reads the same:
//! backtick identifiers, backslash escapes, the `X'…'` literal.
//!
//! Rows are artifacts and this transport claims none of them, per ADR-0024,
//! for the reason the `MariaDB` transport gives: a receive holds no
//! transaction to claim one in. **A row is consumed by the `accept`
//! statement, after its cycle**, its name bound in place of `?`
//! (`transport::sql::accept`); a refused row is left and not received
//! again while unchanged; a failed one is read again.
//!
//! The origin URI carries what the row knew: `mysql://server/orders?row=41`.
//! A send target is `mysql://host:3306/<database>/<table>/<column>`,
//! `host:3306/<database>/<table>/<column>`, or `<table>/<column>` on the
//! configured server and database.

pub mod caching_sha2_password;

mod configured;

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use mariadb::{Authentication, Client, Expecting, Guard, Insert, Logon, NativePassword, Session};
use sql::MARIADB;
use transport::ArrivalIdentity;
use transport::claim::{NoNativeClaim, ResourceClaim};
use transport::error::{Result, protocol_error};
use transport::listening::{Accepting, Listening};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::pool::{Pooled, alive};
use transport::socket;
use transport::sql::{Column, accept, destination};
use transport::{Arrived, Directions, Login, Pool, Taken, Transport};

pub use caching_sha2_password::{CachingSha2Cache, CachingSha2Password};

/// The scheme a send target opens with and an origin carries.
const SCHEME: &str = "mysql";
/// The schemes a send target may open with.
const SCHEMES: &[&str] = &[SCHEME];

/// The plugins this crate logs in with: MySQL's own first, and the native
/// password a server may still switch an account to.
const PLUGINS: &[&dyn Authentication] = &[&CachingSha2Password, &NativePassword];

/// What a Receive Location runs unless told otherwise.
pub const DEFAULT_QUERY: &str = "SELECT id, payload FROM inbox ORDER BY id";

/// What the loopback pair agrees on: one database, one user and password
/// the far end demands and the near end gives, one table and column the
/// payload is inserted into.
const LOOPBACK_DATABASE: &str = "probe";
const LOOPBACK_USER: &str = "xmip";
const LOOPBACK_PASSWORD: &str = "xmip";
const LOOPBACK_TARGET: &str = "probe/payload";

#[derive(Clone)]
pub struct MySqlTransport {
    server: String,
    database: String,
    login: Login,
    query: String,
    /// The statement run on a row's verdict, its name bound in.
    accept: Option<String>,
    /// The rows refused and left, not received again while unchanged.
    /// Cloned, the same memory.
    refused: accept::RefusedRows,
    column: Column,
    timeout: Option<Duration>,
    /// TLS before the login, where asked for.
    guard: Option<Guard>,
    /// The connections a send inserts on and a receive queries on, logged
    /// in once per server and database and kept.
    connections: Pool<Kept>,
    /// What this transport's far end remembers of a full login. Cloned,
    /// the same memory.
    cache: Arc<CachingSha2Cache>,
}

/// A logged-in connection, kept while the server keeps it open.
pub struct Kept(Client);

impl Pooled for Kept {
    /// While the server has not closed the connection — its `wait_timeout`
    /// closes an idle one. Each `COM_QUERY` is read to its end, so nothing
    /// of one is left for the next.
    fn usable(&mut self) -> bool {
        alive(self.0.socket())
    }
}

impl MySqlTransport {
    /// Speak to the server at `server`, on `database`, as `user` with no
    /// password until one is given.
    #[must_use]
    pub fn new(
        server: impl Into<String>,
        database: impl Into<String>,
        user: impl Into<String>,
    ) -> Self {
        Self {
            server: server.into(),
            database: database.into(),
            login: Login::new(user, ""),
            query: DEFAULT_QUERY.to_string(),
            accept: None,
            refused: accept::RefusedRows::default(),
            column: Column::Binary,
            timeout: None,
            guard: None,
            connections: Pool::new(),
            cache: Arc::default(),
        }
    }

    /// The password the login proves.
    #[must_use]
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.login.password = password.into();
        self
    }

    /// The query a receive runs: the first column is the row's name, the
    /// last is the Stream.
    #[must_use]
    pub fn with_query(mut self, query: impl Into<String>) -> Self {
        self.query = query.into();
        self
    }

    /// The statement run once a row's cycle accepted it, the row's name in
    /// place of the dialect's first parameter (`transport::sql::accept`).
    #[must_use]
    pub fn with_accept(mut self, statement: impl Into<String>) -> Self {
        self.accept = Some(statement.into());
        self
    }

    /// What the payload column holds: bytes unless declared otherwise.
    #[must_use]
    pub const fn holding(mut self, column: Column) -> Self {
        self.column = column;
        self
    }

    /// Give up on a server that stops mid-packet.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Log in under TLS, as `guard` says.
    #[must_use]
    pub fn guarded(mut self, guard: Guard) -> Self {
        self.guard = Some(guard);
        self
    }

    /// Log in to the server.
    ///
    /// # Errors
    /// Where the server could not be reached or refused the login.
    pub fn connect(&self) -> Result<Client> {
        self.connect_to(&self.server, &self.database)
    }

    fn connect_to(&self, server: &str, database: &str) -> Result<Client> {
        let logon = Logon {
            user: &self.login.user,
            password: &self.login.password,
            database,
            plugins: PLUGINS,
            guard: self.guard.as_ref(),
        };
        Ok(Client::connect(server, &logon, self.timeout)?)
    }

    /// One query or statement on the connection kept for `server` and
    /// `database`, logged in on the first.
    fn exchange<T>(
        &self,
        server: &str,
        database: &str,
        mut work: impl FnMut(&mut Client) -> mariadb::Result<T>,
    ) -> Result<T> {
        self.connections.exchange(
            &format!("{server}/{database}"),
            || self.connect_to(server, database).map(Kept),
            |kept| Ok(work(&mut kept.0)?),
        )
    }

    /// Bind as the far end clients connect to, and report the address.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.server)
    }

    /// The login this transport's far end admits: its user and password,
    /// checked by `caching_sha2_password` against its cache.
    #[must_use]
    pub fn expecting(&self) -> Expecting<'_> {
        Expecting::new(&self.login.user, &self.login.password, &*self.cache)
    }

    /// Accept one client on an already-bound listener, demanding this
    /// transport's user and password.
    ///
    /// # Errors
    /// Where the connection could not be accepted or the login failed.
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Session> {
        let (stream, _) = socket::accept_tcp(listener, self.timeout)?;
        Ok(Session::accept(stream, &self.expecting())?)
    }

    /// The Stream `insert` carries, as this transport's column holds it,
    /// its origin where `session` received it.
    #[must_use]
    pub fn taken(&self, session: &Session, insert: Insert) -> Taken {
        let origin = format!(
            "{SCHEME}://{}/{}/{}/{}",
            session.peer(),
            session.database(),
            insert.table,
            insert.column
        );
        Taken::new(origin, self.column.stored(insert.literal))
    }
}

impl Transport for MySqlTransport {
    fn name(&self) -> &'static str {
        SCHEME
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("a poll reads again what is not yet told")
    }

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Polled("a receive runs the query and returns")
    }

    /// Run the query on the connection kept for the server and database;
    /// each row is a Stream, whole. Its verdict runs the `accept` statement
    /// where one is declared — on `Accepted`, never on `Refused` or
    /// `Failed` — and tells the database nothing where none is.
    fn receive_up_to(&self, most: usize) -> Result<Vec<Arrived>> {
        let result = self.exchange(&self.server, &self.database, |client| {
            client.query(&self.query)
        })?;
        let shared = Arc::new(self.clone());
        accept::arrivals(
            result.rows,
            most,
            &self.refused,
            |name| format!("{SCHEME}://{}/{}?row={name}", self.server, self.database),
            Clone::clone,
            |value| self.column.bytes(&value, &MARIADB),
            |name| {
                let transport = Arc::clone(&shared);
                accept::accepting(&MARIADB, self.accept.as_deref(), name, move |sql| {
                    transport.exchange(&transport.server, &transport.database, |client| {
                        client.execute(sql).map(|_| ())
                    })
                })
            },
        )
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Gathered("an INSERT carries the body as one literal in its statement")
    }

    /// Insert the bytes as one column of one row, on the connection kept
    /// for the server and database.
    fn send_from(&self, target: &str, outgoing: transport::Outgoing<'_>) -> Result<()> {
        let bytes: &[u8] = &outgoing.gather()?;
        let to = destination(SCHEMES, target, &self.server, &self.database)?;
        let literal = self.column.literal(bytes, &MARIADB)?;
        let insert = MARIADB.insert(to.table, to.column, &literal);
        self.exchange(to.server, to.database, |client| {
            client.execute(&insert).map(|_| ())
        })
    }

    /// Rows are artifacts, and one receive holds no transaction to claim
    /// one in.
    fn claims(&self) -> Option<&dyn ResourceClaim> {
        Some(&NoNativeClaim)
    }
}

impl MySqlTransport {
    /// Both ends on this machine: an ephemeral local port, a login with a
    /// password, so `caching_sha2_password` is spoken whole, the loopback
    /// timeout.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0", LOOPBACK_DATABASE, LOOPBACK_USER)
            .with_password(LOOPBACK_PASSWORD)
            .timing_out_after(LOOPBACK_TIMEOUT)
    }
}

impl Accepting for MySqlTransport {
    fn take_one(self, listener: &TcpListener) -> Result<Taken> {
        // The client keeps its connection for the next insert.
        let mut session = self.accept_one(listener)?;
        let insert = session
            .next_insert()?
            .ok_or_else(|| protocol_error("the client closed without inserting"))?;
        Ok(self.taken(&session, insert))
    }
}

impl Loopback for MySqlTransport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::Unnamed(
            "a row names no sender: the database it was read from is in its origin",
        )
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        Ok(Box::new(Listening::new(self.clone(), self.bind()?)))
    }

    /// INSERT the payload as one column of one row from a fresh near end
    /// logging in to `address` as this transport does.
    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        let near = Self {
            server: address.to_string(),
            ..self.clone()
        };
        near.send(LOOPBACK_TARGET, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::Configured;
    use transport::error::TransportError;
    use transport::payload::edge_payloads;
    use xcore::settings::Applies;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn mysql_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(MySqlTransport::SETTINGS.problems(), Vec::<String>::new());
        let text = |name: &str, value: &str| (name.to_string(), Given::Text(value.to_string()));
        let given = [
            text("database", "orders"),
            text("user", "xmip"),
            ("tls".to_string(), Given::Boolean(true)),
        ];
        let built = MySqlTransport::open("db:3306", Applies::Receive, &given).expect("built");
        assert_eq!(
            (built.server.as_str(), built.database.as_str()),
            ("db:3306", "orders")
        );
        assert_eq!(built.query, DEFAULT_QUERY);
        assert!(
            built.guard.as_ref().expect("guarded").name.is_none(),
            "the host's name"
        );
        assert_eq!(built.name(), "mysql");
    }

    #[test]
    fn the_first_login_is_full_over_the_servers_key_and_the_next_is_fast() {
        let far_end = MySqlTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = MySqlTransport::new(address, "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let sending = near.clone();
        let sender = std::thread::spawn(move || {
            sending.send("inbox/payload", b"first")?;
            sending.connect()?.close()?;
            Ok::<_, TransportError>(())
        });
        assert!(
            !far_end.cache.holds(),
            "a server just started holds no account"
        );
        let mut session = far_end.accept_one(&listener).expect("full");
        assert!(far_end.cache.holds(), "a full login is remembered");
        let insert = session.next_insert().expect("insert").expect("one");
        assert_eq!(far_end.taken(&session, insert).bytes, b"first");
        far_end.accept_one(&listener).expect("fast");
        sender.join().expect("thread").expect("sending");
    }

    #[test]
    fn a_wrong_password_is_refused_after_the_full_authentication() {
        let far_end = MySqlTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let sender = std::thread::spawn(move || {
            MySqlTransport::new(address, "orders", "xmip")
                .with_password("wrong")
                .timing_out_after(secs(5))
                .send("inbox/payload", b"x")
        });
        let error = far_end.accept_one(&listener).err().expect("refused");
        assert!(error.message.contains("Access denied for user 'xmip'"));
        let refused = sender.join().expect("thread").expect_err("refused");
        assert!(!refused.retryable);
        assert!(
            refused.message.contains("1045 (28000)"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_full_login_under_tls_sends_the_password_inside_it() {
        let signed = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("a certificate");
        let served = tls::server_config(
            signed.cert.pem().as_bytes(),
            signed.key_pair.serialize_pem().as_bytes(),
        )
        .expect("server config");
        let trust = tls::trusting(signed.cert.pem().as_bytes()).expect("trust");
        let far_end = MySqlTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let near = MySqlTransport::new(address, "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5))
            .guarded(Guard {
                trust: Some(Arc::new(trust)),
                name: Some("localhost".into()),
            });
        let sender = std::thread::spawn(move || near.send("inbox/payload", b"guarded"));
        let (stream, _) = socket::accept_tcp(&listener, Some(secs(5))).expect("accepted");
        let expecting = far_end.expecting().guarded(Arc::new(served));
        let mut session = Session::accept(stream, &expecting).expect("logged in");
        assert!(session.guarded());
        assert!(far_end.cache.holds(), "the password came whole, under TLS");
        let insert = session.next_insert().expect("insert").expect("one");
        assert_eq!(far_end.taken(&session, insert).bytes, b"guarded");
        sender.join().expect("thread").expect("sending");
    }

    #[test]
    fn a_server_switching_an_account_to_the_native_password_is_answered_in_it() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let address = listener.local_addr().expect("address").to_string();
        let far = std::thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            stream.set_read_timeout(Some(secs(5))).expect("timeout");
            let expecting = Expecting::new("xmip", "secret", &NativePassword)
                .greeting_in(caching_sha2_password::CACHING_SHA2_PASSWORD);
            Session::accept(stream, &expecting).map(Session::serve)
        });
        let near = MySqlTransport::new(address, "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        near.connect().expect("switched").close().expect("quit");
        far.join().expect("thread").expect("login").expect("served");
    }

    #[test]
    fn a_receive_runs_the_query_and_accept_consumes_the_accepted_row() {
        let far_end = MySqlTransport::new("127.0.0.1:0", "orders", "xmip")
            .with_password("secret")
            .timing_out_after(secs(5));
        let (listener, address) = far_end.bind().expect("binding");
        let receiver = std::thread::spawn(move || {
            let near = MySqlTransport::new(address, "orders", "xmip")
                .with_password("secret")
                .with_accept("DELETE FROM inbox WHERE id = ?")
                .timing_out_after(secs(5));
            let mut arrived = near.receive()?;
            assert_eq!(arrived.len(), 2);
            assert!(arrived[0].origin_uri.starts_with("mysql://"));
            arrived.remove(0).taken()?;
            arrived.remove(0).failed()?;
            Ok::<_, TransportError>(())
        });
        let rows: [&[Option<&str>]; 2] = [&[Some("41"), Some("X'61'")], &[Some("42"), None]];
        let session = far_end
            .accept_one(&listener)
            .expect("accepting")
            .with_table(&["id", "payload"], &rows);
        let events = session.serve().expect("served");
        receiver.join().expect("thread").expect("receiving");
        assert_eq!(
            events,
            [
                mariadb::Event::Selected(DEFAULT_QUERY.into()),
                mariadb::Event::Executed("DELETE FROM inbox WHERE id = '41'".into()),
            ]
        );
    }

    #[test]
    fn the_loopback_returns_the_edge_payloads_whole() {
        let pair = MySqlTransport::loopback();
        for (name, payload) in edge_payloads() {
            assert!(pair.refuses(&payload).is_none(), "{name}");
            let arrived = pair.round(&payload).expect(name);
            assert_eq!(arrived.bytes, payload, "{name}");
            assert!(arrived.origin_uri.starts_with("mysql://127.0.0.1:"));
        }
    }
}
