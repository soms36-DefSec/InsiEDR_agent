use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use log::{debug, info, warn};
use tokio::sync::broadcast;

use crate::etw::session::EtwSession;
use crate::etw::types::{EtwDnsQuery, EtwEvent, EtwImageLoad, EtwProcessStart, EtwProcessStop};

#[derive(Default)]
pub struct EtwBuffers {
    pub process_starts: Vec<EtwProcessStart>,
    pub process_stops: Vec<EtwProcessStop>,
    pub image_loads: Vec<EtwImageLoad>,
    pub dns_queries: Vec<EtwDnsQuery>,
}

#[derive(Clone)]
pub struct EtwCollectorHub {
    buffers: Arc<Mutex<EtwBuffers>>,
    active: Arc<AtomicBool>,
}

static GLOBAL_HUB: std::sync::OnceLock<EtwCollectorHub> = std::sync::OnceLock::new();

impl EtwCollectorHub {
    pub fn new() -> Self {
        Self {
            buffers: Arc::new(Mutex::new(EtwBuffers::default())),
            active: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn global() -> &'static EtwCollectorHub {
        GLOBAL_HUB.get_or_init(EtwCollectorHub::new)
    }

    pub fn is_active(&self) -> bool {
        self.active.load(Ordering::SeqCst)
    }

    pub fn start_consumer(&self, mut rx: broadcast::Receiver<EtwEvent>) {
        self.active.store(true, Ordering::SeqCst);
        let buffers_clone = self.buffers.clone();
        let active_clone = self.active.clone();

        std::thread::Builder::new()
            .name("insiedr-etw-hub".to_string())
            .spawn(move || {
                debug!("ETW Hub consumer thread active");
                while active_clone.load(Ordering::SeqCst) {
                    match rx.blocking_recv() {
                        Ok(event) => {
                            if let Ok(mut buf) = buffers_clone.lock() {
                                match event {
                                    EtwEvent::ProcessStart(ps) => {
                                        // Bound buffer size to 5000 to prevent runaway memory
                                        if buf.process_starts.len() < 5000 {
                                            buf.process_starts.push(ps);
                                        }
                                    }
                                    EtwEvent::ProcessStop(ps) => {
                                        if buf.process_stops.len() < 5000 {
                                            buf.process_stops.push(ps);
                                        }
                                    }
                                    EtwEvent::ImageLoad(il) => {
                                        if buf.image_loads.len() < 5000 {
                                            buf.image_loads.push(il);
                                        }
                                    }
                                    EtwEvent::DnsQuery(dq) => {
                                        if buf.dns_queries.len() < 5000 {
                                            buf.dns_queries.push(dq);
                                        }
                                    }
                                }
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(missed)) => {
                            warn!("ETW Hub consumer lagged by {} events", missed);
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            debug!("ETW Hub broadcast channel closed");
                            break;
                        }
                    }
                }
                active_clone.store(false, Ordering::SeqCst);
            })
            .expect("Failed to spawn ETW Hub thread");
    }

    pub fn drain_process_events(&self) -> (Vec<EtwProcessStart>, Vec<EtwProcessStop>, Vec<EtwImageLoad>) {
        if let Ok(mut buf) = self.buffers.lock() {
            let starts = std::mem::take(&mut buf.process_starts);
            let stops = std::mem::take(&mut buf.process_stops);
            let images = std::mem::take(&mut buf.image_loads);
            (starts, stops, images)
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        }
    }

    pub fn drain_dns_queries(&self) -> Vec<EtwDnsQuery> {
        if let Ok(mut buf) = self.buffers.lock() {
            std::mem::take(&mut buf.dns_queries)
        } else {
            Vec::new()
        }
    }
}

pub fn initialize_etw() -> Option<EtwSession> {
    match EtwSession::start() {
        Ok(session) => {
            let rx = session.subscribe();
            EtwCollectorHub::global().start_consumer(rx);
            info!("ETW real-time kernel streaming initialized and attached to Collector Hub");
            Some(session)
        }
        Err(err) => {
            warn!("ETW kernel streaming not started ({}); operating in user-mode snapshot fallback", err);
            None
        }
    }
}
