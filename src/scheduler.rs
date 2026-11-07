use crate::{Error, Result};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex, Notify},
    time::Instant,
};

#[derive(Clone, Default)]
pub struct Cancellation {
    inner: Arc<CancelState>,
}
#[derive(Default)]
struct CancelState {
    cancelled: AtomicBool,
    notify: Notify,
}
impl Cancellation {
    pub fn cancel(&self) {
        self.inner.cancelled.store(true, Ordering::Release);
        self.inner.notify.notify_waiters();
    }
    pub fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }
    pub async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
    pub async fn run<T>(&self, future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
        tokio::select! { biased; () = self.cancelled() => Err(Error::Cancelled), result = future => result }
    }
}

pub struct RateLimiter {
    next: Mutex<Instant>,
    interval: Duration,
}
impl RateLimiter {
    pub fn new(per_second: u32) -> Result<Self> {
        if !(1..=1000).contains(&per_second) {
            return Err(Error::Config("rate must be 1..=1000 probes/second".into()));
        }
        Ok(Self {
            next: Mutex::new(Instant::now()),
            interval: Duration::from_secs_f64(1.0 / per_second as f64),
        })
    }
    pub async fn acquire(&self, cancel: &Cancellation) -> Result<()> {
        cancel
            .run(async {
                let mut next = self.next.lock().await;
                tokio::time::sleep_until(*next).await;
                *next = Instant::now() + self.interval;
                Ok(())
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn cancellation_is_sticky_and_wakes_all() {
        let cancel = Cancellation::default();
        let copy = cancel.clone();
        let task = tokio::spawn(async move { copy.cancelled().await });
        cancel.cancel();
        task.await.unwrap();
        assert!(matches!(
            cancel.run(async { Ok(()) }).await,
            Err(Error::Cancelled)
        ));
    }
}
