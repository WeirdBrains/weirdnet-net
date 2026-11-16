//! The ingress peer's side: TCP 443 (and 80) in, `/weirdnet/ingress/1` streams out.
use super::grant::{Binding, Registered, Registration};
use super::sni::{self, Hello};
use super::{GRANT_PROTOCOL, IngressGrant, MAX_REGISTRATION, proxy, read_msg, write_msg};
use crate::error::{NetError, Result};
use crate::node::{Message, Node, Opener};
use crate::profile::Profile;
use crate::stream::{Incoming, Limits};
use futures::{AsyncReadExt, AsyncWriteExt};
use libp2p::{Multiaddr, PeerId};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt as _;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::compat::TokioAsyncReadCompatExt;

/// How an ingress runs.
#[derive(Debug, Clone)]
pub struct IngressConfig {
    /// Where to take HTTPS (usually `0.0.0.0:443`); `None`: not at all.
    pub https: Option<SocketAddr>,
    /// Where to take plain HTTP (usually `0.0.0.0:80`) for ACME HTTP-01 and redirects.
    pub http: Option<SocketAddr>,
    /// Forward sites at all (off: registrations are refused and nothing is forwarded).
    pub enabled: bool,
    /// Names never forwarded here (lowercase).
    pub blocked: Vec<String>,
    /// How long a client has to send its ClientHello or HTTP request head.
    pub hello_timeout: Duration,
    /// Names one user may register on this ingress.
    pub max_names_per_user: usize,
    /// Names this device serves itself on the same port, and the local address that does
    /// (a relay's own WebSocket-over-TLS listener): passed there as they are, no PROXY header.
    pub local: Vec<(String, SocketAddr)>,
}

impl Default for IngressConfig {
    fn default() -> Self {
        IngressConfig {
            https: None,
            http: None,
            enabled: true,
            blocked: vec![],
            hello_timeout: Duration::from_secs(10),
            max_names_per_user: 64,
            local: vec![],
        }
    }
}

/// A name this ingress forwards, and to whom.
#[derive(Debug, Clone)]
pub struct Site {
    pub name: String,
    pub user: String,
    pub host: PeerId,
    pub addrs: Vec<Multiaddr>,
    pub expires: i64,
}

struct Inner {
    me: PeerId,
    profile: &'static Profile,
    sites: Mutex<HashMap<String, Site>>,
    blocked: Mutex<HashSet<String>>,
    enabled: AtomicBool,
    binding: Arc<dyn Binding>,
    opener: Opener,
    max_names: usize,
    hello_timeout: Duration,
    local: HashMap<String, SocketAddr>,
}

/// A running ingress. Dropping it stops taking connections and registrations.
pub struct Ingress {
    inner: Arc<Inner>,
    https: Option<SocketAddr>,
    http: Option<SocketAddr>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Drop for Ingress {
    fn drop(&mut self) {
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Ingress {
    /// Start forwarding on `node`: take registrations on `/weirdnet/ingress-grant/1` and
    /// listen where `cfg` says. `binding` decides who holds a name ([`super::DnsBinding`]).
    pub fn start<Q: Message, R: Message>(node: &Node<Q, R>, cfg: IngressConfig, binding: Arc<dyn Binding>) -> Result<Ingress> {
        let rt = node.runtime();
        let inner = Arc::new(Inner {
            me: node.peer_id(),
            profile: node.profile(),
            sites: Mutex::new(HashMap::new()),
            blocked: Mutex::new(cfg.blocked.iter().map(|n| n.to_ascii_lowercase()).collect()),
            enabled: AtomicBool::new(cfg.enabled),
            binding,
            opener: node.opener(super::INGRESS_PROTOCOL, Limits::default()),
            max_names: cfg.max_names_per_user,
            hello_timeout: cfg.hello_timeout,
            local: cfg.local.iter().filter_map(|(n, a)| Some((sni::host_name(n.as_bytes())?, *a))).collect(),
        });
        let regs = node.accept_streams(GRANT_PROTOCOL, Limits { backlog: 64, ..Limits::default() })?;
        let mut tasks = vec![rt.spawn(registrations(inner.clone(), regs))];
        let bind = |a: SocketAddr| -> Result<TcpListener> {
            let l = std::net::TcpListener::bind(a).map_err(|e| NetError::Network(format!("cannot listen on {a}: {e}")))?;
            l.set_nonblocking(true).map_err(NetError::net)?;
            let _g = rt.enter();
            TcpListener::from_std(l).map_err(NetError::net)
        };
        let mut https = None;
        if let Some(a) = cfg.https {
            let l = bind(a)?;
            https = l.local_addr().ok();
            tasks.push(rt.spawn(serve(inner.clone(), l, false)));
        }
        let mut http = None;
        if let Some(a) = cfg.http {
            let l = bind(a)?;
            http = l.local_addr().ok();
            tasks.push(rt.spawn(serve(inner.clone(), l, true)));
        }
        Ok(Ingress { inner, https, http, tasks })
    }

    /// Where HTTPS is taken (the bound address, port 0 resolved).
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.https
    }

    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.http
    }

    /// The names registered now (expired ones dropped).
    pub fn sites(&self) -> Vec<Site> {
        let now = crate::now_ms();
        let mut s = self.inner.sites.lock().unwrap_or_else(|e| e.into_inner());
        s.retain(|_, v| v.expires > now);
        let mut v: Vec<Site> = s.values().cloned().collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    /// Stop forwarding `name` here, now and for later registrations (an abuse report, or
    /// this device's own blacklist).
    pub fn revoke(&self, name: &str) {
        let n = name.trim_end_matches('.').to_ascii_lowercase();
        self.inner.sites.lock().unwrap_or_else(|e| e.into_inner()).remove(&n);
        self.inner.blocked.lock().unwrap_or_else(|e| e.into_inner()).insert(n);
    }

    /// Allow a revoked name again (its host has to register again).
    pub fn unrevoke(&self, name: &str) {
        self.inner.blocked.lock().unwrap_or_else(|e| e.into_inner()).remove(&name.trim_end_matches('.').to_ascii_lowercase());
    }

    pub fn revoked(&self) -> Vec<String> {
        let mut v: Vec<String> = self.inner.blocked.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect();
        v.sort();
        v
    }

    /// Turn site forwarding on or off for this device.
    pub fn set_enabled(&self, on: bool) {
        self.inner.enabled.store(on, Ordering::Relaxed);
    }

    pub fn enabled(&self) -> bool {
        self.inner.enabled.load(Ordering::Relaxed)
    }
}

impl Inner {
    fn site(&self, name: &str) -> Option<Site> {
        if !self.enabled.load(Ordering::Relaxed) || self.blocked.lock().ok()?.contains(name) {
            return None;
        }
        let s = self.sites.lock().ok()?.get(name).cloned()?;
        (s.expires > crate::now_ms()).then_some(s)
    }

    async fn register(&self, from: PeerId, reg: Registration) -> Registered {
        let now = crate::now_ms();
        let mut out = Registered::default();
        let addrs: Vec<Multiaddr> = reg.addrs.iter().take(16).filter_map(|a| a.parse().ok()).collect();
        for g in reg.grants.into_iter().take(self.max_names) {
            match self.check(&from, &reg.cert, &g, now).await {
                Ok(()) => {
                    let mut sites = self.sites.lock().unwrap_or_else(|e| e.into_inner());
                    let mine = sites.values().filter(|s| s.user == g.host_user && s.name != g.name).count();
                    if mine >= self.max_names {
                        out.refused.push((g.name, "too many names for this user".into()));
                        continue;
                    }
                    sites.insert(
                        g.name.clone(),
                        Site { name: g.name.clone(), user: g.host_user.clone(), host: from, addrs: addrs.clone(), expires: g.expires },
                    );
                    out.accepted.push(g.name);
                }
                Err(e) => out.refused.push((g.name, e)),
            }
        }
        out
    }

    async fn check(&self, from: &PeerId, cert: &crate::user::NodeCert, g: &IngressGrant, now: i64) -> std::result::Result<(), String> {
        if !self.enabled.load(Ordering::Relaxed) {
            return Err("site forwarding is off on this ingress".into());
        }
        if self.blocked.lock().map(|b| b.contains(&g.name)).unwrap_or(true) {
            return Err("this name is not forwarded here".into());
        }
        g.verify(&self.me, now).map_err(|e| e.to_string())?;
        if !g.covers(self.profile, cert, from) {
            return Err("the node's certificate is not the grant user's".into());
        }
        if !self.binding.check(&g.name, &g.host_user).await {
            return Err(format!("DNS does not bind {} to this user (_weirdnet TXT)", g.name));
        }
        Ok(())
    }
}

async fn registrations(inner: Arc<Inner>, mut regs: Incoming) {
    while let Some(s) = regs.next().await {
        let inner = inner.clone();
        tokio::spawn(async move {
            let mut s = s;
            let from = s.peer();
            let reply = match tokio::time::timeout(Duration::from_secs(30), read_msg(&mut s, MAX_REGISTRATION)).await {
                Ok(Ok(b)) => match serde_json::from_slice::<Registration>(&b) {
                    Ok(reg) => inner.register(from, reg).await,
                    Err(e) => Registered { accepted: vec![], refused: vec![("*".into(), format!("bad registration: {e}"))] },
                },
                _ => return,
            };
            if let Ok(b) = serde_json::to_vec(&reply) {
                let _ = write_msg(&mut s, &b).await;
            }
            let _ = s.close().await;
            tokio::time::sleep(Duration::from_secs(2)).await;
        });
    }
}

async fn serve(inner: Arc<Inner>, l: TcpListener, http: bool) {
    loop {
        let Ok((tcp, client)) = l.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let inner = inner.clone();
        tokio::spawn(async move {
            let _ = tcp.set_nodelay(true);
            let local = tcp.local_addr().unwrap_or(client);
            let r = if http { forward_http(&inner, tcp, client, local).await } else { forward_tls(&inner, tcp, client, local).await };
            if let Err(e) = r {
                tracing::debug!("ingress: {client}: {e}");
            }
        });
    }
}

async fn forward_tls(inner: &Inner, mut tcp: TcpStream, client: SocketAddr, local: SocketAddr) -> std::result::Result<(), String> {
    let mut buf = Vec::with_capacity(2048);
    let name = tokio::time::timeout(inner.hello_timeout, async {
        loop {
            match sni::peek(&buf) {
                Hello::More => {}
                Hello::Name(n) => return Ok(n),
                Hello::NoName => return Err("no server name".to_string()),
                Hello::Bad => return Err("not a TLS ClientHello".to_string()),
            }
            let mut chunk = [0u8; 4096];
            let n = tcp.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("closed before the ClientHello".to_string());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .map_err(|_| "no ClientHello in time".to_string())??;
    if let Some(to) = inner.local.get(&name) {
        let mut l = TcpStream::connect(to).await.map_err(|e| format!("local {to}: {e}"))?;
        tokio::io::AsyncWriteExt::write_all(&mut l, &buf).await.map_err(|e| e.to_string())?;
        splice(tcp, l.compat()).await;
        return Ok(());
    }
    let site = inner.site(&name).ok_or_else(|| format!("{name} is not forwarded here"))?;
    let mut s = (inner.opener)(site.host, site.addrs.clone()).await.map_err(|e| format!("cannot reach the host of {name}: {e}"))?;
    s.write_all(&proxy::encode(client, local, &name, false)).await.map_err(|e| e.to_string())?;
    s.write_all(&buf).await.map_err(|e| e.to_string())?;
    splice(tcp, s).await;
    Ok(())
}

const ACME: &str = "/.well-known/acme-challenge/";

async fn forward_http(inner: &Inner, mut tcp: TcpStream, client: SocketAddr, local: SocketAddr) -> std::result::Result<(), String> {
    let mut buf = Vec::with_capacity(1024);
    let end = tokio::time::timeout(inner.hello_timeout, async {
        loop {
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                return Ok(i + 4);
            }
            if buf.len() > 8192 {
                return Err("request head too large".to_string());
            }
            let mut chunk = [0u8; 2048];
            let n = tcp.read(&mut chunk).await.map_err(|e| e.to_string())?;
            if n == 0 {
                return Err("closed before the request".to_string());
            }
            buf.extend_from_slice(&chunk[..n]);
        }
    })
    .await
    .map_err(|_| "no request in time".to_string())??;
    let head = String::from_utf8_lossy(&buf[..end]).to_string();
    let mut lines = head.split("\r\n");
    let mut req = lines.next().unwrap_or("").split(' ');
    let (_method, path) = (req.next().unwrap_or(""), req.next().unwrap_or("/"));
    let host = lines
        .filter_map(|l| l.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case("host"))
        .map(|(_, v)| {
            v.trim().rsplit_once(':').filter(|(_, p)| p.chars().all(|c| c.is_ascii_digit())).map(|(h, _)| h).unwrap_or(v.trim()).to_string()
        })
        .and_then(|h| sni::host_name(h.as_bytes()));
    let mut tcp = tcp.compat();
    let Some(host) = host else {
        let _ = tcp.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
        return Err("no usable Host".into());
    };
    if path.starts_with(ACME)
        && let Some(site) = inner.site(&host)
    {
        let mut s = (inner.opener)(site.host, site.addrs.clone()).await.map_err(|e| format!("cannot reach the host of {host}: {e}"))?;
        s.write_all(&proxy::encode(client, local, &host, true)).await.map_err(|e| e.to_string())?;
        s.write_all(&buf).await.map_err(|e| e.to_string())?;
        splice(tcp.into_inner(), s).await;
        return Ok(());
    }
    let path = if path.starts_with('/') { path } else { "/" };
    let resp = format!("HTTP/1.1 301 Moved Permanently\r\nLocation: https://{host}{path}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    let _ = tcp.write_all(resp.as_bytes()).await;
    let _ = tcp.close().await;
    Ok(())
}

/// Copy both ways until both sides have closed.
async fn splice<S: futures::AsyncRead + futures::AsyncWrite + Unpin>(tcp: TcpStream, s: S) {
    let (tr, tw) = tcp.compat().split();
    let (sr, sw) = s.split();
    let up = async move {
        let mut sw = sw;
        let _ = futures::io::copy(tr, &mut sw).await;
        let _ = sw.close().await;
    };
    let down = async move {
        let mut tw = tw;
        let _ = futures::io::copy(sr, &mut tw).await;
        let _ = tw.close().await;
    };
    futures::join!(up, down);
}
