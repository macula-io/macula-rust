//! An in-memory station on the other end of a session's control stream, for
//! tests of the session reader and of what runs on sessions, such as the
//! pool. The names match the Go and .NET test helpers.

use super::*;
use tokio::io::DuplexStream;

pub(crate) const WAIT: Duration = Duration::from_secs(2);
pub(crate) const REALM: [u8; 32] = [7; 32];

/// The station end of a session's control stream. What the session
/// writes reaches the station through a pipe that holds one byte, so a
/// station that stops reading stalls the session's write mid-frame, as a
/// station withholding flow-control credit does.
pub(crate) struct FakeStation {
    pub(crate) identity: KeyPair,
    to_session: DuplexStream,
    frames: mpsc::UnboundedReceiver<Value>,
    reading: watch::Sender<bool>,
}

pub(crate) type Ended = oneshot::Receiver<(SessionEndReason, bool)>;

pub(crate) fn connect() -> (Arc<Channel>, FakeStation, Ended) {
    connect_with(SEND_TIMEOUT)
}

pub(crate) fn connect_with(send_timeout: Duration) -> (Arc<Channel>, FakeStation, Ended) {
    let (ended_tx, ended_rx) = oneshot::channel();
    let (channel, station) = connect_ending(
        send_timeout,
        Box::new(move |reason, closed_here| {
            let _ = ended_tx.send((reason.clone(), closed_here));
        }),
    );
    (channel, station, ended_rx)
}

pub(crate) fn connect_ending(
    send_timeout: Duration,
    on_ended: OnEnded,
) -> (Arc<Channel>, FakeStation) {
    let (session_writes, station_reads) = tokio::io::duplex(1);
    let (station_writes, session_reads) = tokio::io::duplex(READ_CHUNK);
    let identity = KeyPair::generate();
    let channel = Channel::start(
        Box::new(session_reads),
        Vec::new(),
        Box::new(session_writes),
        KeyPair::generate(),
        identity.node_id(),
        send_timeout,
        on_ended,
    );
    let (frames_tx, frames) = mpsc::unbounded_channel();
    let (reading, reading_rx) = watch::channel(true);
    tokio::spawn(read_session_frames(station_reads, frames_tx, reading_rx));
    (
        channel,
        FakeStation {
            identity,
            to_session: station_writes,
            frames,
            reading,
        },
    )
}

async fn read_session_frames(
    mut pipe: DuplexStream,
    frames: mpsc::UnboundedSender<Value>,
    mut reading: watch::Receiver<bool>,
) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        if reading.wait_for(|reading| *reading).await.is_err() {
            return;
        }
        let Ok(n) = pipe.read(&mut chunk).await else {
            return;
        };
        if n == 0 {
            return;
        }
        buf.extend_from_slice(&chunk[..n]);
        while let Ok(Decoded::Frame(value, consumed)) = frame::decode(&buf) {
            buf.drain(..consumed);
            if frames.send(value).is_err() {
                return;
            }
        }
    }
}

pub(crate) enum Signer {
    Caller,
    Other(Box<KeyPair>),
    Nobody,
}

impl FakeStation {
    pub(crate) async fn send(&mut self, frame: &Value) {
        self.send_raw(&frame::encode(frame).expect("the test frame encodes"))
            .await;
    }

    pub(crate) async fn send_raw(&mut self, bytes: &[u8]) {
        self.to_session
            .write_all(bytes)
            .await
            .expect("the session's pipe is open");
    }

    pub(crate) async fn next_frame(&mut self) -> Value {
        tokio::time::timeout(WAIT, self.frames.recv())
            .await
            .expect("the session sent a frame in time")
            .expect("the session's pipe is open")
    }

    pub(crate) async fn next(&mut self, frame_type: &str) -> Value {
        loop {
            let frame = self.next_frame().await;
            if text_field(&frame, "frame_type").as_deref() == Some(frame_type) {
                return frame;
            }
        }
    }

    pub(crate) async fn reply(&mut self, call: &Value, text: &str) {
        let call_id = frame::frame_call_id(call).expect("a CALL carries its call_id");
        let result = frame::result(&frame::ResultSpec::new(
            call_id,
            Value::text(text),
            self.identity.node_id(),
        ));
        self.send(&result).await;
    }

    pub(crate) async fn send_event(&mut self, topic: &str, payload: &str) {
        let event = Value::Map(vec![
            (Value::text("frame_type"), Value::text("event")),
            (Value::text("realm"), Value::Bytes(REALM.to_vec())),
            (
                Value::text("topic"),
                Value::Bytes(topic.as_bytes().to_vec()),
            ),
            (
                Value::text("publisher"),
                Value::Bytes(self.identity.node_id().to_vec()),
            ),
            (Value::text("seq"), Value::Int(1)),
            (Value::text("payload"), Value::text(payload)),
            (Value::text("delivered_via"), Value::text("direct")),
        ]);
        self.send(&event).await;
    }

    /// An inbound CALL as a station relays one. Returns its call_id.
    pub(crate) async fn send_inbound_call(&mut self, procedure: &str, signer: Signer) -> [u8; 16] {
        self.send_inbound_call_due(procedure, signer, now_ms() + 5_000)
            .await
    }

    /// [`send_inbound_call`](Self::send_inbound_call), due at `deadline_ms`.
    pub(crate) async fn send_inbound_call_due(
        &mut self,
        procedure: &str,
        signer: Signer,
        deadline_ms: i128,
    ) -> [u8; 16] {
        let caller = KeyPair::generate();
        let spec = CallSpec::new(
            rand::random(),
            procedure,
            REALM,
            Value::Null,
            deadline_ms,
            caller.node_id(),
        );
        let unsigned = frame::call(&spec);
        let call = match signer {
            Signer::Caller => frame::sign(unsigned, &caller),
            Signer::Other(other) => frame::sign(unsigned, &other),
            Signer::Nobody => unsigned,
        };
        self.send(&call).await;
        spec.call_id
    }

    pub(crate) fn stall_session_writes(&self) {
        self.reading.send_replace(false);
    }

    pub(crate) fn resume_session_writes(&self) {
        self.reading.send_replace(true);
    }

    /// Whether the session sends no frame for `wait`.
    pub(crate) async fn nothing_sent_within(&mut self, wait: Duration) -> bool {
        tokio::time::timeout(wait, self.frames.recv())
            .await
            .is_err()
    }
}

pub(crate) fn now_ms() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after 1970")
        .as_millis() as i128
}

pub(crate) fn call(procedure: &str) -> CallSpec {
    CallSpec::new(
        rand::random(),
        procedure,
        REALM,
        Value::Null,
        now_ms() + 5_000,
        KeyPair::generate().node_id(),
    )
}

pub(crate) fn subscribe(topic: &str) -> SubscribeSpec {
    SubscribeSpec::new(topic, REALM, KeyPair::generate().node_id())
}

pub(crate) fn publish(topic: &str) -> Value {
    let publisher = KeyPair::generate();
    frame::sign(
        frame::publish(&frame::PublishSpec::new(
            topic,
            REALM,
            publisher.node_id(),
            1,
            Value::text("tick"),
            now_ms() as u64,
        )),
        &publisher,
    )
}

pub(crate) fn spawn_call(
    channel: &Arc<Channel>,
    spec: CallSpec,
    timeout: Duration,
) -> JoinHandle<Result<CallResponse, CallError>> {
    let channel = channel.clone();
    tokio::spawn(async move {
        channel
            .call(&spec, &KeyPair::generate(), timeout, None)
            .await
    })
}

pub(crate) fn reply_text(response: CallResponse) -> String {
    match response {
        CallResponse::Result {
            payload: Value::Text(text),
            ..
        } => text,
        other => panic!("expected a text RESULT, got {other:?}"),
    }
}

pub(crate) fn event_text(event: EventInfo) -> String {
    match event.payload {
        Value::Text(text) => text,
        other => panic!("expected a text payload, got {other:?}"),
    }
}

pub(crate) fn frame_type(frame: &Value) -> String {
    text_field(frame, "frame_type").expect("a frame carries its frame_type")
}

/// Resolves once some other writer holds the turn to write.
pub(crate) async fn turn_taken(channel: &Channel) {
    tokio::time::timeout(WAIT, async {
        while channel.writer.try_lock().is_ok() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a writer took the turn in time");
}

/// Keeps every log line a test run writes, for tests that check what was
/// logged. The log crate takes one logger for the whole process, so every
/// such test installs this same one and picks its own lines by a node id.
struct CapturingLogger;

static LOGGED: Mutex<Vec<(log::Level, String)>> = Mutex::new(Vec::new());

impl log::Log for CapturingLogger {
    fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        lock(&LOGGED).push((record.level(), record.args().to_string()));
    }

    fn flush(&self) {}
}

pub(crate) fn capture_logs() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = log::set_logger(&CapturingLogger);
        log::set_max_level(log::LevelFilter::Info);
    });
}

/// The captured lines that name `node_id`, in the order they were logged.
pub(crate) fn logged_about(node_id: &[u8; 32]) -> Vec<(log::Level, String)> {
    let node_id = hex(node_id);
    lock(&LOGGED)
        .iter()
        .filter(|(_, line)| line.contains(&node_id))
        .cloned()
        .collect()
}
