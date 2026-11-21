//! The voice transport (voice-transport-v3.md): a WebRTC data channel, kept
//! behind [`Link`]'s send / receive / close so the room logic never sees it.
//!
//! str0m is sans-IO: one task owns the UDP socket and the peer. The hub is
//! ICE-lite and answers with its host candidates, so no STUN or TURN is used.
//! One data channel, negotiated on stream 0, unordered, no retransmission.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use str0m::change::{SdpAnswer, SdpPendingOffer};
use str0m::channel::{ChannelConfig, ChannelId, Reliability};
use str0m::net::{Protocol, Receive};
use str0m::{Candidate, Event, IceConnectionState, Input, Output, Rtc};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

/// A packet that still fits one SCTP chunk in a 1280-byte path MTU; larger
/// ones are split, and losing any piece loses the frame.
pub(super) const MAX_PACKET: usize = 1200;

/// An open voice channel. Dropping it (or [`Link::close`]) ends the session.
pub(super) struct Link {
    outbound: mpsc::UnboundedSender<Vec<u8>>,
    inbound: Mutex<mpsc::UnboundedReceiver<Vec<u8>>>,
}

impl Link {
    pub(super) fn send(&self, packet: &[u8]) -> Result<(), String> {
        self.outbound
            .send(packet.to_vec())
            .map_err(|_| "voice data channel closed".to_string())
    }

    pub(super) async fn recv(&self) -> Result<Vec<u8>, String> {
        self.inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| "voice data channel closed".to_string())
    }
}

/// An offer waiting for `voice_rtc_answer`.
pub(super) struct Offer {
    rtc: Rtc,
    socket: UdpSocket,
    local: SocketAddr,
    channel: ChannelId,
    pending: SdpPendingOffer,
}

impl Offer {
    /// The offer for the hub at `hub_host`, with its SDP. The candidate is
    /// the address the OS routes to that host from: what the hub will see.
    pub(super) async fn new(hub_host: &str) -> Result<(Self, String), String> {
        let local_ip = route_to(hub_host).await?;
        let socket = UdpSocket::bind((local_ip, 0))
            .await
            .map_err(|e| e.to_string())?;
        let local = socket.local_addr().map_err(|e| e.to_string())?;
        let mut rtc = Rtc::builder().build(Instant::now());
        rtc.add_local_candidate(Candidate::host(local, "udp").map_err(|e| e.to_string())?);
        let mut change = rtc.sdp_api();
        let channel = change.add_channel_with_config(ChannelConfig {
            label: "voice".to_string(),
            ordered: false,
            reliability: Reliability::MaxRetransmits { retransmits: 0 },
            negotiated: Some(0),
            protocol: String::new(),
        });
        let (offer, pending) = change.apply().ok_or("no WebRTC offer to make")?;
        Ok((
            Self {
                rtc,
                socket,
                local,
                channel,
                pending,
            },
            offer.to_sdp_string(),
        ))
    }

    /// Applies the answer and starts the I/O task.
    pub(super) fn accept(mut self, answer: &str) -> Result<Link, String> {
        let answer = SdpAnswer::from_sdp_string(answer).map_err(|e| e.to_string())?;
        self.rtc
            .sdp_api()
            .accept_answer(self.pending, answer)
            .map_err(|e| e.to_string())?;
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let (in_tx, in_rx) = mpsc::unbounded_channel();
        tokio::spawn(run(
            self.rtc,
            self.socket,
            self.local,
            self.channel,
            out_rx,
            in_tx,
        ));
        Ok(Link {
            outbound: out_tx,
            inbound: Mutex::new(in_rx),
        })
    }
}

/// Connecting a UDP socket sends nothing; it only resolves the route.
async fn route_to(host: &str) -> Result<IpAddr, String> {
    let target = tokio::net::lookup_host((host, 9))
        .await
        .map_err(|e| e.to_string())?
        .find(|a| a.is_ipv4())
        .ok_or("hub host has no IPv4 address")?;
    let probe = UdpSocket::bind("0.0.0.0:0")
        .await
        .map_err(|e| e.to_string())?;
    probe.connect(target).await.map_err(|e| e.to_string())?;
    Ok(probe.local_addr().map_err(|e| e.to_string())?.ip())
}

async fn run(
    mut rtc: Rtc,
    socket: UdpSocket,
    local: SocketAddr,
    channel: ChannelId,
    mut outbound: mpsc::UnboundedReceiver<Vec<u8>>,
    inbound: mpsc::UnboundedSender<Vec<u8>>,
) {
    let mut buf = vec![0u8; 2000];
    loop {
        let deadline = loop {
            if !rtc.is_alive() {
                return;
            }
            match rtc.poll_output() {
                Ok(Output::Timeout(t)) => break t,
                Ok(Output::Transmit(t)) => {
                    let _ = socket.send_to(&t.contents, t.destination).await;
                }
                Ok(Output::Event(Event::ChannelData(d))) if d.id == channel => {
                    if inbound.send(d.data).is_err() {
                        return;
                    }
                }
                Ok(Output::Event(Event::IceConnectionStateChange(
                    IceConnectionState::Disconnected,
                ))) => return,
                Ok(Output::Event(_)) => {}
                Err(_) => return,
            }
        };
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(100));
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                if let Ok((n, source)) = received {
                    if let Ok(contents) = buf[..n].try_into() {
                        let _ = rtc.handle_input(Input::Receive(
                            Instant::now(),
                            Receive { proto: Protocol::Udp, source, destination: local, contents },
                        ));
                    }
                }
            }
            packet = outbound.recv() => {
                let Some(packet) = packet else {
                    rtc.disconnect();
                    return;
                };
                if let Some(mut ch) = rtc.channel(channel) {
                    let _ = ch.write(true, &packet);
                }
            }
            _ = tokio::time::sleep(wait) => {}
        }
        let _ = rtc.handle_input(Input::Timeout(Instant::now()));
    }
}
