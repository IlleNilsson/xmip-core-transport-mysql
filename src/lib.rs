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
//! **The transport is every SQL technology's**, `transport::sql`'s
//! `SqlTransport` over this crate's [`MySql`] wire (2026-11-13): a Receive
//! Location runs its query and hands each row up; the `accept` statement
//! consumes a row after its cycle; a Send Location inserts the Stream as
//! one column of one row; what the column holds is the Location's to
//! declare (ADR-0038). The SQL is the `MariaDB` dialect of
//! `xmip-core-library-sql`, which MySQL reads the same: backtick
//! identifiers, backslash escapes, the `X'…'` literal, in the mode the
//! session reads.
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

use mariadb::{Authentication, Client, Expecting, Insert, Logon, NativePassword, Session};
use sql::Dialect;
use tls::ClientSettings;
use transport::error::{Result, protocol_error};
use transport::pool::alive;
use transport::socket;
use transport::sql::{Probe, Rows, SqlTransport, Wire};
use transport::{Login, Taken};
use xcore::settings::{Read, Settings};

pub use caching_sha2_password::{CachingSha2Cache, CachingSha2Password};

/// The plugins this crate logs in with: MySQL's own first, and the native
/// password a server may still switch an account to.
const PLUGINS: &[&dyn Authentication] = &[&CachingSha2Password, &NativePassword];

/// A Location over a MySQL server.
pub type MySqlTransport = SqlTransport<MySql>;

/// MySQL's wire: `xmip-core-library-mariadb`'s client with MySQL's
/// logins, TLS before the login where asked for, and the far end's memory
/// of a full login.
#[derive(Clone, Default)]
pub struct MySql {
    /// TLS before the login, where asked for.
    guard: Option<ClientSettings>,
    /// What this technology's far end remembers of a full login. Cloned,
    /// the same memory.
    cache: Arc<CachingSha2Cache>,
}

impl MySql {
    /// Logging in under TLS, as `guard` says.
    #[must_use]
    pub fn guarded(guard: ClientSettings) -> Self {
        Self {
            guard: Some(guard),
            cache: Arc::default(),
        }
    }

    /// The TLS a login is guarded by, where one is.
    #[must_use]
    pub const fn guard(&self) -> Option<&ClientSettings> {
        self.guard.as_ref()
    }

    /// What the far end remembers of a full login.
    #[must_use]
    pub fn cache(&self) -> &CachingSha2Cache {
        &self.cache
    }
}

impl Wire for MySql {
    type Client = Client;

    const NAME: &'static str = "mysql";
    const SCHEMES: &'static [&'static str] = &["mysql"];
    const SETTINGS: &'static Settings = configured::SETTINGS;
    /// A login with a password, so `caching_sha2_password` is spoken whole.
    const PROBE: Probe = Probe {
        database: "probe",
        user: "xmip",
        password: "xmip",
        target: "probe/payload",
    };

    fn dialect() -> &'static Dialect {
        &sql::MARIADB
    }

    /// The session's mode: a backslash escaped, or itself where the
    /// server's status flags carry `NO_BACKSLASH_ESCAPES`.
    fn session_dialect(client: &Client) -> Option<&'static Dialect> {
        Some(client.dialect())
    }

    fn configured(self, settings: &Read) -> Result<Self> {
        Ok(Self {
            guard: transport::sql::client_tls(settings),
            ..self
        })
    }

    fn connect(
        &self,
        server: &str,
        database: &str,
        presented: &Login,
        timeout: Option<Duration>,
    ) -> Result<Client> {
        let logon = Logon {
            user: &presented.user,
            password: &presented.password,
            database,
            plugins: PLUGINS,
            guard: self.guard.as_ref(),
        };
        Ok(Client::connect(server, &logon, timeout)?)
    }

    /// While the server has not closed the connection — its `wait_timeout`
    /// closes an idle one. Each `COM_QUERY` is read to its end, so nothing
    /// of one is left for the next.
    fn usable(client: &mut Client) -> bool {
        alive(client.socket())
    }

    fn query(client: &mut Client, sql: &str) -> Result<Rows<String>> {
        Ok(client.query(sql)?.rows)
    }

    fn execute(client: &mut Client, sql: &str) -> Result<()> {
        client.execute(sql)?;
        Ok(())
    }

    /// The key a login in the clear is answered with, made before the far
    /// end is bound.
    fn ready_far_end(&self) {
        CachingSha2Cache::ready();
    }

    /// The client keeps its connection for the next insert.
    fn take_one(transport: &MySqlTransport, listener: &TcpListener) -> Result<Taken> {
        let mut session = accept_one(transport, listener)?;
        let insert = session
            .next_insert()?
            .ok_or_else(|| protocol_error("the client closed without inserting"))?;
        Ok(taken(transport, &session, insert))
    }
}

/// The login `transport`'s far end admits: its user and password, checked
/// by `caching_sha2_password` against its cache.
#[must_use]
pub fn expecting(transport: &MySqlTransport) -> Expecting<'_> {
    let login = transport.login();
    Expecting::new(&login.user, &login.password, transport.wire().cache())
}

/// Accept one client on a listener `transport` bound, demanding its user
/// and password.
///
/// # Errors
/// Where the connection could not be accepted or the login failed.
pub fn accept_one(transport: &MySqlTransport, listener: &TcpListener) -> Result<Session> {
    let (stream, _) = socket::accept_tcp(listener, transport.timeout())?;
    Ok(Session::accept(stream, &expecting(transport))?)
}

/// The Stream `insert` carries, as `transport`'s column holds it, its
/// origin where `session` received it.
#[must_use]
pub fn taken(transport: &MySqlTransport, session: &Session, insert: Insert) -> Taken {
    MySqlTransport::inserted(
        session.peer(),
        session.database(),
        &insert.table,
        &insert.column,
        transport.column().stored(insert.literal),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::error::TransportError;
    use transport::payload::edge_payloads;
    use transport::sql::DEFAULT_QUERY;
    use transport::{Configured, Loopback, Transport};
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
        assert_eq!((built.server(), built.database()), ("db:3306", "orders"));
        assert_eq!(built.query(), DEFAULT_QUERY);
        assert!(
            built.wire().guard().expect("guarded").name().is_none(),
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
            !far_end.wire().cache().holds(),
            "a server just started holds no account"
        );
        let mut session = accept_one(&far_end, &listener).expect("full");
        assert!(far_end.wire().cache().holds(), "a full login is remembered");
        let insert = session.next_insert().expect("insert").expect("one");
        assert_eq!(taken(&far_end, &session, insert).bytes, b"first");
        accept_one(&far_end, &listener).expect("fast");
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
        let error = accept_one(&far_end, &listener).err().expect("refused");
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
            signed.signing_key.serialize_pem().as_bytes(),
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
            .with_wire(MySql::guarded(
                ClientSettings::trusting(Arc::new(trust)).named("localhost"),
            ));
        let sender = std::thread::spawn(move || near.send("inbox/payload", b"guarded"));
        let (stream, _) = socket::accept_tcp(&listener, Some(secs(5))).expect("accepted");
        let expecting = expecting(&far_end).guarded(Arc::new(served));
        let mut session = Session::accept(stream, &expecting).expect("logged in");
        assert!(session.guarded());
        assert!(
            far_end.wire().cache().holds(),
            "the password came whole, under TLS"
        );
        let insert = session.next_insert().expect("insert").expect("one");
        assert_eq!(taken(&far_end, &session, insert).bytes, b"guarded");
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
        let session = accept_one(&far_end, &listener)
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

    /// The Essentials runs one pair's rounds from its workers at once: each
    /// round its own far end, every near end the pair's pool and the far
    /// ends its one cache, the first logins full while it holds nothing.
    #[test]
    fn rounds_of_one_pair_at_once_each_return_their_payload() {
        const ROUNDS: usize = 16;
        let pair = MySqlTransport::loopback();
        std::thread::scope(|scope| {
            let rounds: Vec<_> = (0..ROUNDS)
                .map(|n| {
                    let pair = &pair;
                    scope.spawn(move || pair.round(format!("round {n}").as_bytes()))
                })
                .collect();
            for (n, round) in rounds.into_iter().enumerate() {
                let arrived = round.join().expect("thread").expect("round");
                assert_eq!(arrived.bytes, format!("round {n}").as_bytes());
            }
        });
    }
}
