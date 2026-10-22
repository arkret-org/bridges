//! Independent workers retain one genuine Device reader per host incarnation.

use std::collections::{BTreeMap, BTreeSet};

use tokio::sync::Semaphore;
use tokio::task::JoinHandle;

use super::*;

struct Worker {
    device: Arc<ManagedDevice>,
    reader: Arc<ManagedDeviceReader>,
    task: JoinHandle<()>,
    retired: bool,
}
impl Drop for Worker {
    fn drop(&mut self) {
        // Invalidate late results synchronously, before task cancellation is
        // next polled. Durable work stays in the host's encrypted custody.
        self.reader.retire();
        self.task.abort();
    }
}

/// Retain this set across host ticks and drop it with the Applet instance.
/// Each worker owns its own protocol progress; a slow Account cannot hold
/// the other Devices behind its network operations.
pub struct ManagedDeviceWorkers {
    runtime: Arc<ManagedDeviceRuntime>,
    permits: Arc<Semaphore>,
    workers: BTreeMap<String, Worker>,
    content_sink: Option<Arc<dyn NativeContentSink>>,
    configurations: Arc<crate::applet_configuration::AppletConfigurationService>,
    configuration_recovery: Option<JoinHandle<Result<usize>>>,
}

impl Drop for ManagedDeviceWorkers {
    fn drop(&mut self) {
        if let Some(task) = &self.configuration_recovery {
            task.abort();
        }
    }
}

impl ManagedDeviceWorkers {
    pub fn new(edge: Arc<ArkretEdge>) -> Result<Self> {
        Ok(Self {
            configurations: Arc::new(
                crate::applet_configuration::AppletConfigurationService::new(edge.clone())?,
            ),
            configuration_recovery: None,
            runtime: Arc::new(ManagedDeviceRuntime::new(edge)?),
            permits: Arc::new(Semaphore::new(8)),
            workers: BTreeMap::new(),
            content_sink: None,
        })
    }

    pub fn with_content_sink(mut self, sink: Arc<dyn NativeContentSink>) -> Self {
        self.content_sink = Some(sink);
        self
    }

    /// Explicit host shutdown waits for cancelled network futures to release
    /// their private stores. Drop still retires every reader immediately.
    pub async fn shutdown(mut self) {
        if let Some(mut task) = self.configuration_recovery.take() {
            task.abort();
            let _ = (&mut task).await;
        }
        for worker in self.workers.values_mut() {
            worker.reader.retire();
            worker.task.abort();
        }
        for worker in self.workers.values_mut() {
            let _ = (&mut worker.task).await;
        }
    }

    pub async fn tick(&mut self) -> Result<()> {
        if self
            .configuration_recovery
            .as_ref()
            .is_some_and(|task| task.is_finished())
            && let Some(task) = self.configuration_recovery.take()
        {
            match task.await {
                Ok(Ok(_)) => {}
                result => tracing::warn!(?result, "configuration recovery will retry"),
            }
        }
        if self.configuration_recovery.is_none() {
            let configurations = self.configurations.clone();
            self.configuration_recovery = Some(tokio::spawn(async move {
                configurations.recover_accepted_configurations().await
            }));
        }
        let fenced = self.runtime.reconcile_device_revocations().await?;
        let mut settled_revocations = Vec::new();
        for (id, worker) in &mut self.workers {
            if fenced.iter().any(|(actor, device)| {
                actor == &worker.device.actor_id && device == &worker.device.device_id
            }) {
                worker.retired = true;
                worker.reader.retire();
                worker.task.abort();
                if self.runtime.erase_revoked_device(&worker.device).await? {
                    settled_revocations.push(id.clone());
                }
            }
        }
        for id in settled_revocations {
            self.workers.remove(&id);
        }
        let devices = self.runtime.bootstrap_configured_devices().await?;
        if !self
            .runtime
            .edge
            .config()
            .arkret
            .managed_actor_authoring
            .device
            .as_ref()
            .is_some_and(|config| config.mls)
        {
            self.workers.clear();
            return Ok(());
        }
        let mut active = BTreeSet::new();
        let mut active_scopes = BTreeSet::new();
        for device in devices {
            if fenced
                .iter()
                .any(|(actor, id)| actor == &device.actor_id && id == &device.device_id)
            {
                continue;
            }
            let id = canonical_sha256(&(
                &device.actor_id,
                &device.device_id,
                &device.authorization_event_id,
                &device.governance_station,
                device.governance_generation,
                &device.effective_scope,
            ))?;
            active.insert(id.clone());
            active_scopes.insert(canonical_sha256(&(
                &device.actor_id,
                &device.effective_scope,
            ))?);
            if self
                .workers
                .get(&id)
                .is_some_and(|worker| !worker.retired && !worker.task.is_finished())
            {
                continue;
            }
            let reader = match self.runtime.open_reader(&device).await {
                Ok(reader) => Arc::new(reader),
                Err(error) => {
                    tracing::warn!(account = %device.actor_id, %error, "native reader remains unavailable");
                    continue;
                }
            };
            let device = Arc::new(device);
            let task = spawn_worker(
                self.runtime.clone(),
                device.clone(),
                reader.clone(),
                self.permits.clone(),
                self.content_sink.clone(),
            );
            self.workers.insert(
                id,
                Worker {
                    device,
                    reader,
                    task,
                    retired: false,
                },
            );
        }
        let mut settled = Vec::new();
        for (id, worker) in &mut self.workers {
            if active.contains(id) {
                continue;
            }
            // A transient bootstrap failure can omit an Account. Absence
            // alone never declares that its accepted Device was replaced.
            if active_scopes.contains(&canonical_sha256(&(
                &worker.device.actor_id,
                &worker.device.effective_scope,
            ))?) {
                worker.retired = true;
                worker.reader.retire();
                worker.task.abort();
            }
            if !worker.retired && !worker.task.is_finished() {
                continue;
            }
            if let Err(error) = cleanup(&self.runtime, &worker.device).await {
                tracing::warn!(account = %worker.device.actor_id, %error, "retired native Device cleanup remains pending");
                continue;
            }
            if !self
                .runtime
                .has_pending_recipient_work(&worker.device)
                .await?
            {
                settled.push(id.clone());
            }
        }
        for id in settled {
            self.workers.remove(&id);
        }
        Ok(())
    }
}

async fn cleanup(runtime: &ManagedDeviceRuntime, device: &ManagedDevice) -> Result<()> {
    runtime.drain_durable_welcome_consumes(device).await?;
    runtime.complete_durable_recipient_page(device).await?;
    Ok(())
}

fn spawn_worker(
    runtime: Arc<ManagedDeviceRuntime>,
    device: Arc<ManagedDevice>,
    reader: Arc<ManagedDeviceReader>,
    permits: Arc<Semaphore>,
    sink: Option<Arc<dyn NativeContentSink>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let Ok(_permit) = permits.acquire().await else {
                break;
            };
            if let Err(error) = cleanup(&runtime, &device).await {
                tracing::warn!(account = %device.actor_id, %error, "native durable cleanup remains pending");
                continue;
            }
            if reader.client().check_context().is_err() {
                break;
            }
            match runtime.poll_welcome_queue(&device, &reader).await {
                Ok(_) => {}
                Err(error) => tracing::warn!(account = %device.actor_id, %error,
                    "native recipient recovery remains pending"),
            }
            if let Err(error) = runtime.poll_content_stream(&device, &reader).await {
                tracing::warn!(account = %device.actor_id, %error,
                    "native stream recovery remains pending");
            }
            if let Some(sink) = sink.as_ref() {
                if let Err(error) = sink.flush(&device, &reader).await {
                    tracing::warn!(actor = %device.actor_id, %error, "native adapter output remains pending");
                }
                if let Err(error) = runtime.drain_content(&device, &reader, sink.as_ref()).await {
                    tracing::warn!(actor = %device.actor_id, %error, "native content delivery remains pending");
                }
            }
        }
    })
}
