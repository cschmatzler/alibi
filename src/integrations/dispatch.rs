//! Router-owned dispatch continues after a fully buffered client request disconnects.

use crate::BetterAuth;
use better_auth_core::{AuthError, AuthRequest, AuthResponse, AuthSchema};
use std::sync::{Arc, Mutex};
use tokio::{
    sync::{mpsc, oneshot},
    task::{Id, JoinSet},
};
use tracing::{Instrument, instrument::WithSubscriber};

type DispatchResult = Result<AuthResponse, AuthError>;
type DispatchFuture = std::pin::Pin<Box<dyn Future<Output = DispatchResult> + Send>>;

struct DispatchJob<R> {
    future: DispatchFuture,
    reply: oneshot::Sender<R>,
}

pub(super) struct DispatchSupervisor<R> {
    sender: Arc<Mutex<Option<mpsc::UnboundedSender<DispatchJob<R>>>>>,
    render: fn(DispatchResult) -> R,
}

impl<R> Clone for DispatchSupervisor<R> {
    fn clone(&self) -> Self {
        Self {
            sender: Arc::clone(&self.sender),
            render: self.render,
        }
    }
}

impl<R: Send + 'static> DispatchSupervisor<R> {
    pub(super) fn new(render: fn(DispatchResult) -> R) -> Self {
        Self {
            sender: Arc::new(Mutex::new(None)),
            render,
        }
    }

    pub(super) async fn dispatch<S: AuthSchema>(
        &self,
        auth: Arc<BetterAuth<S>>,
        request: AuthRequest,
    ) -> R {
        let failure = || (self.render)(Err(AuthError::internal("Authentication request failed")));
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return failure();
        };
        let (reply, receive) = oneshot::channel();
        let future = Box::pin(
            async move { auth.handle_request(request).await }
                .instrument(tracing::Span::current())
                .with_current_subscriber(),
        );
        let submitted = self.sender.lock().is_ok_and(|mut sender| {
            // A router can outlive its runtime. Never retry accepted jobs.
            if sender
                .as_ref()
                .is_some_and(mpsc::UnboundedSender::is_closed)
            {
                *sender = None;
            }
            let sender = sender.get_or_insert_with(|| {
                let (send, receive) = mpsc::unbounded_channel();
                // The actor holds no sender or auth reference; router drop drains work.
                let _supervisor = runtime.spawn(supervise_dispatches(receive, self.render));
                send
            });
            sender.send(DispatchJob { future, reply }).is_ok()
        });
        if !submitted {
            return failure();
        }
        receive.await.unwrap_or_else(|_| failure())
    }
}

async fn supervise_dispatches<R: Send + 'static>(
    mut receive: mpsc::UnboundedReceiver<DispatchJob<R>>,
    render: fn(DispatchResult) -> R,
) {
    let mut workers = JoinSet::new();
    let mut replies = std::collections::HashMap::<Id, oneshot::Sender<R>>::new();
    let mut accepting = true;
    while accepting || !workers.is_empty() {
        tokio::select! {
            job = receive.recv(), if accepting => match job {
                Some(job) => {
                    let id = workers.spawn(job.future).id();
                    drop(replies.insert(id, job.reply));
                }
                None => accepting = false,
            },
            completed = workers.join_next_with_id(), if !workers.is_empty() => {
                if let Some(completed) = completed {
                    let (id, result) = match completed {
                        Ok((id, result)) => (id, result),
                        Err(error) => {
                            tracing::error!(panic = error.is_panic(), cancelled = error.is_cancelled(), "Authentication dispatch task failed");
                            (error.id(), Err(AuthError::internal("Authentication request failed")))
                        }
                    };
                    if let Some(reply) = replies.remove(&id) { drop(reply.send(render(result))); }
                }
            },
        }
    }
}
