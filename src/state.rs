//! Shared, source-agnostic connection and traffic metrics.
//!
//! Aggregate and per-connection counters use atomics so message/byte
//! accounting does not lock. The registry is touched only when connections
//! open, close, or a consumer requests a snapshot.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const DEFAULT_CONNECTION_CAP: usize = 10_000;
pub const DEFAULT_RATE_HISTORY: usize = 60;

pub type ConnId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficDirection {
    In,
    Out,
}

#[derive(Clone, Copy, Debug)]
pub enum ConnectionLifecycle {
    Open { since: Instant },
    Closed { since: Instant, ended: Instant },
}

/// A connection handle kept by a traffic source for lock-free counter updates.
pub struct ConnStats {
    id: ConnId,
    client: SocketAddr,
    server: SocketAddr,
    lifecycle: Mutex<ConnectionLifecycle>,
    encrypted: AtomicBool,
    msgs_in: AtomicU64,
    msgs_out: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
}

#[derive(Clone, Debug)]
pub struct ConnSnapshot {
    pub id: ConnId,
    pub client: SocketAddr,
    pub server: SocketAddr,
    pub lifecycle: ConnectionLifecycle,
    pub encrypted: bool,
    pub msgs_in: u64,
    pub msgs_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct RateSample {
    pub msgs_in: u64,
    pub msgs_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Clone, Debug, Default)]
pub struct MetricsSnapshot {
    pub conns_opened: u64,
    pub conns_live: usize,
    pub msgs_in: u64,
    pub msgs_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub connections: Vec<ConnSnapshot>,
    pub rates: Vec<RateSample>,
}

#[derive(Clone, Debug, Default)]
pub struct MetricsSummary {
    pub conns_opened: u64,
    pub conns_live: usize,
    pub msgs_in: u64,
    pub msgs_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub rates: Vec<RateSample>,
}

struct Registry {
    entries: HashMap<ConnId, Arc<ConnStats>>,
    closed: VecDeque<ConnId>,
}

#[derive(Default)]
struct Totals {
    msgs_in: u64,
    msgs_out: u64,
    bytes_in: u64,
    bytes_out: u64,
}

struct RateHistory {
    previous: Totals,
    samples: VecDeque<RateSample>,
}

pub struct Metrics {
    conns_opened: AtomicU64,
    conns_live: AtomicUsize,
    next_conn_id: AtomicU64,
    msgs_in: AtomicU64,
    msgs_out: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    conns: Mutex<Registry>,
    rates: Mutex<RateHistory>,
    connection_cap: usize,
    rate_history: usize,
}

/// Owns the aggregate rate thread and stops it promptly when dropped.
pub struct RateSampler {
    stop: Option<Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl Drop for RateSampler {
    fn drop(&mut self) {
        self.stop.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub fn new() -> Self {
        Self::with_limits(DEFAULT_CONNECTION_CAP, DEFAULT_RATE_HISTORY)
    }

    pub fn with_limits(connection_cap: usize, rate_history: usize) -> Self {
        Self {
            conns_opened: AtomicU64::new(0),
            conns_live: AtomicUsize::new(0),
            next_conn_id: AtomicU64::new(1),
            msgs_in: AtomicU64::new(0),
            msgs_out: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            conns: Mutex::new(Registry {
                entries: HashMap::new(),
                closed: VecDeque::new(),
            }),
            rates: Mutex::new(RateHistory {
                previous: Totals::default(),
                samples: VecDeque::new(),
            }),
            connection_cap,
            rate_history,
        }
    }

    pub fn open_connection(
        &self,
        client: SocketAddr,
        server: SocketAddr,
        encrypted: bool,
    ) -> Arc<ConnStats> {
        let id = self.next_conn_id.fetch_add(1, Ordering::Relaxed);
        let since = Instant::now();
        let stats = Arc::new(ConnStats {
            id,
            client,
            server,
            lifecycle: Mutex::new(ConnectionLifecycle::Open { since }),
            encrypted: AtomicBool::new(encrypted),
            msgs_in: AtomicU64::new(0),
            msgs_out: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
        });
        let mut registry = self.conns.lock().unwrap();
        registry.entries.insert(id, stats.clone());
        self.conns_opened.fetch_add(1, Ordering::Relaxed);
        self.conns_live.fetch_add(1, Ordering::Relaxed);
        stats
    }

    /// Account for `count` decoded pgwire messages (`bytes` of wire data)
    /// flowing in `direction` on `conn`. Updates both the aggregate totals and
    /// the per-connection counters atomically. Called once per drain batch
    /// (a batch may span several TCP segments / socket reads).
    pub fn record_messages(
        &self,
        conn: &ConnStats,
        direction: TrafficDirection,
        count: u64,
        bytes: u64,
    ) {
        match direction {
            TrafficDirection::In => {
                self.msgs_in.fetch_add(count, Ordering::Relaxed);
                self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
                conn.msgs_in.fetch_add(count, Ordering::Relaxed);
                conn.bytes_in.fetch_add(bytes, Ordering::Relaxed);
            }
            TrafficDirection::Out => {
                self.msgs_out.fetch_add(count, Ordering::Relaxed);
                self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
                conn.msgs_out.fetch_add(count, Ordering::Relaxed);
                conn.bytes_out.fetch_add(bytes, Ordering::Relaxed);
            }
        }
    }

    pub fn set_encrypted(&self, conn: &ConnStats, encrypted: bool) {
        conn.encrypted.store(encrypted, Ordering::Relaxed);
    }

    pub fn close_connection(&self, conn: &ConnStats) {
        let mut lifecycle = conn.lifecycle.lock().unwrap();
        let since = match *lifecycle {
            ConnectionLifecycle::Open { since } => since,
            ConnectionLifecycle::Closed { .. } => return,
        };
        *lifecycle = ConnectionLifecycle::Closed {
            since,
            ended: Instant::now(),
        };
        drop(lifecycle);
        self.conns_live.fetch_sub(1, Ordering::Relaxed);

        let mut registry = self.conns.lock().unwrap();
        registry.closed.push_back(conn.id);
        while registry.entries.len() > self.connection_cap {
            let Some(id) = registry.closed.pop_front() else {
                break; // all retained entries are still open
            };
            registry.entries.remove(&id);
        }
    }

    /// Take the next fixed-interval rate sample. The TUI calls this once per
    /// second; values are deltas from the previous aggregate snapshot.
    pub fn sample_rates(&self) -> RateSample {
        let totals = self.totals();
        let mut history = self.rates.lock().unwrap();
        let sample = RateSample {
            msgs_in: totals.msgs_in.saturating_sub(history.previous.msgs_in),
            msgs_out: totals.msgs_out.saturating_sub(history.previous.msgs_out),
            bytes_in: totals.bytes_in.saturating_sub(history.previous.bytes_in),
            bytes_out: totals.bytes_out.saturating_sub(history.previous.bytes_out),
        };
        history.previous = totals;
        if self.rate_history != 0 {
            history.samples.push_back(sample);
            while history.samples.len() > self.rate_history {
                history.samples.pop_front();
            }
        }
        sample
    }

    /// Start the aggregate one-second sampler. Dropping the returned guard
    /// stops and joins the thread without waiting for the next tick.
    pub fn spawn_rate_sampler(self: &Arc<Self>) -> std::io::Result<RateSampler> {
        if self.rate_history == 0 {
            return Ok(RateSampler {
                stop: None,
                thread: None,
            });
        }
        self.spawn_rate_sampler_every(Duration::from_secs(1))
    }

    fn spawn_rate_sampler_every(
        self: &Arc<Self>,
        interval: Duration,
    ) -> std::io::Result<RateSampler> {
        let (stop, stopped) = mpsc::channel();
        let metrics = self.clone();
        let thread = std::thread::Builder::new()
            .name("tapgres-rates".into())
            .spawn(move || {
                while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(interval) {
                    metrics.sample_rates();
                }
            })?;
        Ok(RateSampler {
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// Snapshot only aggregate fields and rate history. This is cheap enough
    /// for every TUI frame and does not touch retained connection records.
    pub fn summary(&self) -> MetricsSummary {
        let totals = self.totals();
        let rates = self.rates.lock().unwrap().samples.iter().copied().collect();
        MetricsSummary {
            conns_opened: self.conns_opened.load(Ordering::Relaxed),
            conns_live: self.conns_live.load(Ordering::Relaxed),
            msgs_in: totals.msgs_in,
            msgs_out: totals.msgs_out,
            bytes_in: totals.bytes_in,
            bytes_out: totals.bytes_out,
            rates,
        }
    }

    pub fn snapshot(&self) -> MetricsSnapshot {
        let summary = self.summary();
        let registry = self.conns.lock().unwrap();
        let mut connections = Vec::with_capacity(registry.entries.len());
        for conn in registry.entries.values() {
            let lifecycle = *conn.lifecycle.lock().unwrap();
            connections.push(ConnSnapshot {
                id: conn.id,
                client: conn.client,
                server: conn.server,
                lifecycle,
                encrypted: conn.encrypted.load(Ordering::Relaxed),
                msgs_in: conn.msgs_in.load(Ordering::Relaxed),
                msgs_out: conn.msgs_out.load(Ordering::Relaxed),
                bytes_in: conn.bytes_in.load(Ordering::Relaxed),
                bytes_out: conn.bytes_out.load(Ordering::Relaxed),
            });
        }
        drop(registry);
        connections.sort_unstable_by_key(|conn| conn.id);
        MetricsSnapshot {
            conns_opened: summary.conns_opened,
            conns_live: summary.conns_live,
            msgs_in: summary.msgs_in,
            msgs_out: summary.msgs_out,
            bytes_in: summary.bytes_in,
            bytes_out: summary.bytes_out,
            connections,
            rates: summary.rates,
        }
    }

    fn totals(&self) -> Totals {
        Totals {
            msgs_in: self.msgs_in.load(Ordering::Relaxed),
            msgs_out: self.msgs_out.load(Ordering::Relaxed),
            bytes_in: self.bytes_in.load(Ordering::Relaxed),
            bytes_out: self.bytes_out.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn endpoint(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    #[test]
    fn closed_connections_retain_final_counters_with_a_cap() {
        let metrics = Metrics::with_limits(2, 60);
        for port in 1..=3 {
            let conn = metrics.open_connection(endpoint(port), endpoint(5432), false);
            metrics.record_messages(&conn, TrafficDirection::In, 1, port as u64);
            metrics.close_connection(&conn);
        }
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.conns_opened, 3);
        assert_eq!(snapshot.conns_live, 0);
        assert_eq!(snapshot.connections.len(), 2);
        assert_eq!(snapshot.connections[0].client.port(), 2);
        assert_eq!(snapshot.connections[0].bytes_in, 2);
        assert!(matches!(
            snapshot.connections[0].lifecycle,
            ConnectionLifecycle::Closed { .. }
        ));
    }

    #[test]
    fn open_connections_are_not_evicted() {
        let metrics = Metrics::with_limits(1, 60);
        let first = metrics.open_connection(endpoint(1), endpoint(5432), false);
        let second = metrics.open_connection(endpoint(2), endpoint(5432), false);
        metrics.close_connection(&second);
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.connections.len(), 1);
        assert_eq!(snapshot.connections[0].id, first.id);
        assert_eq!(snapshot.conns_live, 1);
    }

    #[test]
    fn rate_samples_are_aggregate_deltas() {
        let metrics = Metrics::with_limits(10, 2);
        let conn = metrics.open_connection(endpoint(1), endpoint(5432), false);
        metrics.record_messages(&conn, TrafficDirection::In, 1, 12);
        metrics.record_messages(&conn, TrafficDirection::Out, 1, 20);
        let first = metrics.sample_rates();
        assert_eq!((first.msgs_in, first.bytes_in), (1, 12));
        assert_eq!((first.msgs_out, first.bytes_out), (1, 20));
        metrics.record_messages(&conn, TrafficDirection::In, 1, 5);
        let second = metrics.sample_rates();
        assert_eq!((second.msgs_in, second.bytes_in), (1, 5));
        assert_eq!((second.msgs_out, second.bytes_out), (0, 0));
    }

    #[test]
    fn managed_sampler_ticks_and_stops() {
        let metrics = Arc::new(Metrics::with_limits(10, 2));
        let conn = metrics.open_connection(endpoint(1), endpoint(5432), false);
        metrics.record_messages(&conn, TrafficDirection::In, 1, 12);
        let sampler = metrics
            .spawn_rate_sampler_every(Duration::from_millis(5))
            .unwrap();
        let deadline = Instant::now() + Duration::from_millis(250);
        while metrics.summary().rates.is_empty() && Instant::now() < deadline {
            std::thread::yield_now();
        }
        assert_eq!(metrics.summary().rates[0].bytes_in, 12);
        drop(sampler);
    }

    #[test]
    fn disabled_rate_history_does_not_start_a_thread() {
        let metrics = Arc::new(Metrics::with_limits(10, 0));
        let sampler = metrics.spawn_rate_sampler().unwrap();
        assert!(sampler.stop.is_none());
        assert!(sampler.thread.is_none());
    }
}
