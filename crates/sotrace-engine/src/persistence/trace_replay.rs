// Legacy bincode replay visitors. Included in the persistence module.
struct StreamingPersistedTrace<P> {
    trace_id: u64,
    so_file_id: u64,
    source: String,
    base_addr: u64,
    events: StreamingTraceEvents<P>,
    created_at: u64,
}

impl<P> Serialize for StreamingPersistedTrace<P>
where
    P: FnOnce(&mut dyn FnMut(TraceEvent) -> Result<()>) -> Result<ImportStats>,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut tuple = serializer.serialize_tuple(6)?;
        tuple.serialize_element(&self.trace_id)?;
        tuple.serialize_element(&self.so_file_id)?;
        tuple.serialize_element(&self.source)?;
        tuple.serialize_element(&self.base_addr)?;
        tuple.serialize_element(&self.events)?;
        tuple.serialize_element(&self.created_at)?;
        tuple.end()
    }
}

#[allow(dead_code)]
struct StreamingTraceEvents<P> {
    event_count: usize,
    producer: RefCell<Option<P>>,
    written: Cell<usize>,
    sorted: Cell<bool>,
    previous_step: Cell<Option<u64>>,
    stats: RefCell<Option<ImportStats>>,
}

impl<P> Serialize for StreamingTraceEvents<P>
where
    P: FnOnce(&mut dyn FnMut(TraceEvent) -> Result<()>) -> Result<ImportStats>,
{
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.event_count))?;
        let producer = self
            .producer
            .borrow_mut()
            .take()
            .ok_or_else(|| S::Error::custom("stream producer was already consumed"))?;
        let mut sink = |event: TraceEvent| -> Result<()> {
            let written = self.written.get();
            if written >= self.event_count {
                return Err(anyhow!("stream producer emitted more events than declared"));
            }
            if let Some(previous) = self.previous_step.get() {
                if event.step() < previous {
                    self.sorted.set(false);
                }
            }
            self.previous_step.set(Some(event.step()));
            sequence
                .serialize_element(&event)
                .map_err(|error| anyhow!(error.to_string()))?;
            self.written.set(written + 1);
            Ok(())
        };
        let stats = producer(&mut sink).map_err(|error| S::Error::custom(error.to_string()))?;
        let result = sequence.end()?;
        *self.stats.borrow_mut() = Some(stats);
        Ok(result)
    }
}

/// Deserializes the stable six-field `PersistedTrace` representation while
/// streaming the `events` sequence to a caller-owned destination.
struct TraceReplaySeed<Start, Event> {
    start: Start,
    on_event: Event,
}

impl<'de, T, Start, Event> DeserializeSeed<'de> for TraceReplaySeed<Start, Event>
where
    Start: FnOnce(&TraceReplayStart) -> Result<T>,
    Event: FnMut(&mut T, TraceEvent) -> Result<()>,
{
    type Value = (T, TraceReplayResult);

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_struct(
            "PersistedTrace",
            &["trace_id", "so_file_id", "source", "base_addr", "events", "created_at"],
            TraceReplayVisitor { start: self.start, on_event: self.on_event },
        )
    }
}

struct TraceReplayVisitor<Start, Event> {
    start: Start,
    on_event: Event,
}

impl<'de, T, Start, Event> Visitor<'de> for TraceReplayVisitor<Start, Event>
where
    Start: FnOnce(&TraceReplayStart) -> Result<T>,
    Event: FnMut(&mut T, TraceEvent) -> Result<()>,
{
    type Value = (T, TraceReplayResult);

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a PersistedTrace in its six-field bincode representation")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let trace_id = next_trace_field(&mut seq, "trace_id")?;
        let so_file_id = next_trace_field(&mut seq, "so_file_id")?;
        let source = next_trace_field(&mut seq, "source")?;
        let base_addr = next_trace_field(&mut seq, "base_addr")?;
        let replay_start = TraceReplayStart { trace_id, so_file_id, source, base_addr };
        let mut state = (self.start)(&replay_start).map_err(A::Error::custom)?;
        let mut on_event = self.on_event;
        let mut event_count = 0;
        next_trace_field_seed(
            &mut seq,
            EventsReplaySeed {
                state: &mut state,
                on_event: &mut on_event,
                event_count: &mut event_count,
            },
            "events",
        )?;
        let created_at = next_trace_field(&mut seq, "created_at")?;

        Ok((
            state,
            TraceReplayResult { start: replay_start, event_count, created_at },
        ))
    }
}

fn next_trace_field<'de, A, T>(seq: &mut A, name: &str) -> std::result::Result<T, A::Error>
where
    A: SeqAccess<'de>,
    T: Deserialize<'de>,
{
    seq.next_element()?
        .ok_or_else(|| A::Error::custom(format!("missing PersistedTrace {}", name)))
}

fn next_trace_field_seed<'de, A, S>(
    seq: &mut A,
    seed: S,
    name: &str,
) -> std::result::Result<S::Value, A::Error>
where
    A: SeqAccess<'de>,
    S: DeserializeSeed<'de>,
{
    seq.next_element_seed(seed)?
        .ok_or_else(|| A::Error::custom(format!("missing PersistedTrace {}", name)))
}

struct EventsReplaySeed<'a, T, Event> {
    state: &'a mut T,
    on_event: &'a mut Event,
    event_count: &'a mut usize,
}

impl<'de, T, Event> DeserializeSeed<'de> for EventsReplaySeed<'_, T, Event>
where
    Event: FnMut(&mut T, TraceEvent) -> Result<()>,
{
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> std::result::Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(EventsReplayVisitor {
            state: self.state,
            on_event: self.on_event,
            event_count: self.event_count,
        })
    }
}

struct EventsReplayVisitor<'a, T, Event> {
    state: &'a mut T,
    on_event: &'a mut Event,
    event_count: &'a mut usize,
}

impl<'de, T, Event> Visitor<'de> for EventsReplayVisitor<'_, T, Event>
where
    Event: FnMut(&mut T, TraceEvent) -> Result<()>,
{
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a sequence of TraceEvent values")
    }

    fn visit_seq<A>(self, mut seq: A) -> std::result::Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        while let Some(event) = seq.next_element::<TraceEvent>()? {
            (self.on_event)(self.state, event).map_err(A::Error::custom)?;
            *self.event_count += 1;
        }
        Ok(())
    }
}

/// Lowercase hex encoding of a byte slice.
fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
