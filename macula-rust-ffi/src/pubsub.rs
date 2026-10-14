//! PubSub through the pool: a publication signed once and sent on the
//! pool's links, and a subscription on every link, each event delivered
//! once. The foreign side reads a subscription with
//! [`FfiSubscription::next`] in a loop of its own, which fits a mobile app's
//! lifecycle better than a native background loop would.

use std::sync::Arc;

use macula_rust::frame::Payload;
use macula_rust::pool::Subscription;
use macula_rust::station_link::{Event, Publication};
use tokio::sync::Mutex;

use crate::pool::FfiPool;
use crate::{millis, to_32, FfiError, FfiValue};

/// A publication a subscription heard, verified: who published it, where,
/// its seq and time, the payload, and how it arrived.
#[derive(uniffi::Record, Debug, Clone, PartialEq)]
pub struct FfiEvent {
    pub publisher: Vec<u8>,
    pub realm: Vec<u8>,
    pub topic: String,
    pub seq: u64,
    pub published_at: u64,
    pub payload: FfiValue,
    pub delivered_via: String,
}

impl TryFrom<Event> for FfiEvent {
    type Error = FfiError;

    fn try_from(e: Event) -> Result<Self, FfiError> {
        // An event that could not be opened carries no payload and the reason
        // it could not be: this boundary carries neither, so it refuses one
        // by name rather than hand the app an empty event.
        if let Some(reason) = e.unopened {
            return Err(FfiError::UnrepresentableValue {
                message: format!("an event that could not be opened: {}", reason.name()),
            });
        }
        let payload = match e.payload {
            Payload::Clear(payload) => payload.try_into()?,
            // A sealed group event. This boundary models no group, so it
            // carries no way to name the epoch or open one. Named here rather
            // than dropped silently, so a subscriber is told why it heard
            // nothing.
            Payload::Sealed(sealed) => {
                return Err(FfiError::UnrepresentableValue {
                    message: format!(
                        "a sealed group event under epoch {} (the FFI has no group API)",
                        sealed.key_id.iter().map(|b| format!("{b:02x}")).collect::<String>()
                    ),
                })
            }
        };
        Ok(FfiEvent {
            publisher: e.publisher.to_vec(),
            realm: e.realm.to_vec(),
            topic: e.topic,
            seq: e.seq,
            published_at: e.published_at,
            payload,
            delivered_via: e.delivered_via,
        })
    }
}

/// The node's subscription to a realm and topic, until
/// [`unsubscribe`](Self::unsubscribe).
#[derive(uniffi::Object)]
pub struct FfiSubscription(Mutex<Option<Subscription>>);

#[uniffi::export(async_runtime = "tokio")]
impl FfiPool {
    /// Signs a publication once and sends it on the pool's links. `ttl_ms`
    /// of `None` is macula's 10 minutes.
    pub async fn publish(
        &self,
        realm: Vec<u8>,
        topic: String,
        payload: FfiValue,
        ttl_ms: Option<u64>,
    ) -> Result<(), FfiError> {
        Ok(self
            .0
            .publish(Publication {
                realm: to_32(realm)?,
                topic,
                payload: Payload::Clear(payload.into()),
                ttl_ms,
            })
            .await?)
    }

    /// Subscribes the node to `topic` in `realm` on every link.
    pub async fn subscribe(
        &self,
        realm: Vec<u8>,
        topic: String,
    ) -> Result<Arc<FfiSubscription>, FfiError> {
        let sub = self.0.subscribe(&to_32(realm)?, &topic).await?;
        Ok(Arc::new(FfiSubscription(Mutex::new(Some(sub)))))
    }
}

#[uniffi::export(async_runtime = "tokio")]
impl FfiSubscription {
    /// The next event, or `None` when none arrives within `timeout_ms`.
    /// [`FfiError::Closed`] once the subscription or its pool has ended.
    pub async fn next(&self, timeout_ms: u64) -> Result<Option<FfiEvent>, FfiError> {
        let mut held = self.0.lock().await;
        let sub = held.as_mut().ok_or(FfiError::Closed)?;
        match tokio::time::timeout(millis(timeout_ms), sub.recv()).await {
            Err(_) => Ok(None),
            Ok(None) => {
                *held = None;
                Err(FfiError::Closed)
            }
            Ok(Some(event)) => Ok(Some(event.try_into()?)),
        }
    }

    /// How many events arrived while the subscription was full.
    pub async fn dropped(&self) -> u64 {
        self.0
            .lock()
            .await
            .as_ref()
            .map(|s| s.dropped())
            .unwrap_or(0)
    }

    /// Ends the subscription on every link.
    pub async fn unsubscribe(&self) -> Result<(), FfiError> {
        let Some(mut sub) = self.0.lock().await.take() else {
            return Ok(());
        };
        Ok(sub.unsubscribe().await?)
    }
}
