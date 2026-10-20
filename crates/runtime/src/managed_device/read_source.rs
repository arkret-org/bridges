//! A live local read capability derived from the original encrypted Device.

use std::sync::atomic::{AtomicBool, Ordering};

use arkret::http_client::own_station_device_results::{
    OwnStationDeviceBinding, OwnStationDeviceClient, OwnStationDeviceInstance,
    OwnStationDeviceSnapshot, OwnStationDeviceSource,
};

use super::*;

struct DeviceReadSource {
    context: OwnStationDeviceSnapshot,
    active: AtomicBool,
}

impl OwnStationDeviceSource for DeviceReadSource {
    fn snapshot(&self) -> arkret::http_client::Result<OwnStationDeviceSnapshot> {
        if !self.active.load(Ordering::Acquire) {
            return Err(arkret::http_client::Error::Protocol(
                "managed Device reader was retired".into(),
            ));
        }
        Ok(self.context.clone())
    }
}

/// Own this lease for exactly one worker incarnation. Dropping it invalidates
/// cloned clients and late responses instead of lending them a new worker's
/// authorization. The Station still checks every operation's current cut.
pub struct ManagedDeviceReader {
    client: OwnStationDeviceClient,
    source: Arc<DeviceReadSource>,
}

impl ManagedDeviceReader {
    pub fn client(&self) -> &OwnStationDeviceClient {
        &self.client
    }
    pub(super) fn check_device(&self, device: &ManagedDevice) -> Result<()> {
        self.client.check_context()?;
        let context = self.client.context()?;
        if context.actor_id() != &device.actor_id
            || context.device_id() != &device.device_id
            || context.authorization_event_id() != &device.authorization_event_id
            || context.effective_scope() != &device.effective_scope
        {
            return Err(invalid(
                "native reader belongs to another original Device or scope",
            ));
        }
        Ok(())
    }
    pub fn retire(&self) {
        self.source.active.store(false, Ordering::Release);
    }
}

impl Drop for ManagedDeviceReader {
    fn drop(&mut self) {
        self.retire();
    }
}

impl ManagedDeviceRuntime {
    pub async fn open_reader(&self, device: &ManagedDevice) -> Result<ManagedDeviceReader> {
        self.accepted_device_record(device).await?;
        self.terminal_child(device, "ak.event.read").await?;
        let realm = device
            .actor_id
            .as_realm_actor_id()
            .ok_or_else(|| invalid("Realm actor required"))?
            .realm_id
            .clone();
        let route = self.edge.realm_route(&realm).await?;
        if route.authority.current_service_id() != &device.governance_station
            || route.authority.current_generation() != device.governance_generation
        {
            return Err(invalid(
                "Device reader must be rebuilt for the current governance tenure",
            ));
        }
        let description = device.client().describe().await?;
        let binding =
            OwnStationDeviceBinding::from_description(device.client().base_url(), &description)?;
        let (_, _, record) = self.accepted_device_record(device).await?;
        let authorization = payload(&record)?;
        let expires_at = authorization
            .expires_at
            .flatten()
            .ok_or_else(|| invalid("native reader has no original finite Device window"))?;
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|error| invalid(error.to_string()))?;
        let metadata = AppletManagedDeviceMetadata {
            actor_id: device.actor_id.clone(),
            device_id: device.device_id.clone(),
            authorization_event_id: device.authorization_event_id.clone(),
            applet_id: authorization
                .applet_id
                .ok_or_else(|| invalid("native reader has no accepted Applet"))?,
            effective_scope: device.effective_scope.clone(),
            nonce: arkret::base64url_encode(nonce),
        };
        let key = SigningKey::from_bytes(&seed(&record.device_seed)?);
        let context = OwnStationDeviceSnapshot::new(
            binding,
            &route.authority,
            &metadata,
            key.verifying_key().to_bytes(),
            authorization.not_before,
            expires_at,
            0,
            OwnStationDeviceInstance::default(),
        )?;
        let source = Arc::new(DeviceReadSource {
            context,
            active: AtomicBool::new(true),
        });
        let client = OwnStationDeviceClient::new(device.client().clone(), source.clone())?;
        Ok(ManagedDeviceReader { client, source })
    }
}
