//! Archive authority is an explicit manager capability, separate from the
//! authoring object retained by daily Device workers.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock, Weak};
mod handover;
mod history;
#[cfg(test)]
mod maintenance_tests;
mod series;
pub(crate) use handover::ArchiveCustodyAcceptance;

use super::*;
use crate::manager_archive::ManagerArchiveVault;

fn deployment_vaults() -> &'static Mutex<BTreeMap<PathBuf, Weak<ManagerArchiveVault>>> {
    static VAULTS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<ManagerArchiveVault>>>> = OnceLock::new();
    VAULTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

pub struct ManagedActorManagerService {
    pub(crate) authoring: Arc<ManagedActorAuthoringService>,
    pub(crate) vault: Arc<ManagerArchiveVault>,
    maintenance: Mutex<Weak<ManagerArchiveMaintenance>>,
}

/// A host-owned lifetime for manager work. Device workers never receive it.
pub struct ManagerArchiveMaintenance {
    task: tokio::task::JoinHandle<()>,
}
impl ManagerArchiveMaintenance {
    /// Request termination when the host retires, even if a router still holds
    /// another guard. This does not roll back an already submitted operation.
    pub fn stop(&self) {
        self.task.abort();
    }
}
impl Drop for ManagerArchiveMaintenance {
    fn drop(&mut self) {
        self.stop();
    }
}

impl ManagedActorManagerService {
    /// Validate operator key separation before opening a durable archive. This
    /// pure preflight does not grant manager authority or bind a vault owner.
    pub fn validate_archive_wrapping_key(
        edge: &runtime::ArkretEdge,
        key: &arkret::KeyBytes,
    ) -> Result<()> {
        if key.as_slice().len() != 32 {
            return Err(BridgeError::Config(
                "manager archive wrapping key must contain exactly 32 bytes".into(),
            ));
        }
        let config = edge.config();
        let daily = arkret::KeyBytes::new(
            config
                .arkret
                .managed_actor_authoring
                .key_encryption_key()?
                .to_vec(),
        );
        let signing = arkret::KeyBytes::new(config.signing_seed()?.to_vec());
        for existing in [&daily, &signing] {
            let difference = key
                .as_slice()
                .iter()
                .zip(existing.as_slice())
                .fold(0u8, |difference, (left, right)| difference | (left ^ right));
            if difference == 0 {
                return Err(BridgeError::Config(
                    "manager archive wrapping key must be independent of daily authoring and Service signing keys".into(),
                ));
            }
        }
        Ok(())
    }

    pub fn new(edge: Arc<runtime::ArkretEdge>, vault: Arc<ManagerArchiveVault>) -> Result<Self> {
        let authoring = Arc::new(ManagedActorAuthoringService::new(edge)?);
        vault.require_distinct_authoring_key(&authoring.key_encryption_key)?;
        vault.require_distinct_authoring_key(&authoring.config.signing_seed()?)?;
        vault.bind_manager(
            &AppletId::new(authoring.edge.applet_id())?,
            authoring.edge.service_actor_id(),
        )?;
        Ok(Self {
            authoring,
            vault,
            maintenance: Mutex::new(Weak::new()),
        })
    }

    pub fn start_maintenance(self: &Arc<Self>) -> Result<Arc<ManagerArchiveMaintenance>> {
        let mut existing = self
            .maintenance
            .lock()
            .map_err(|_| BridgeError::Runtime("manager maintenance lock unavailable".into()))?;
        if let Some(existing) = existing.upgrade() {
            return Ok(existing);
        }
        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            BridgeError::Runtime("manager maintenance requires the host runtime".into())
        })?;
        let service = self.clone();
        let task = runtime.spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(15));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                if let Err(error) = service.maintain_known_backup_series().await {
                    tracing::warn!(%error, "manager archive maintenance will retry");
                }
            }
        });
        let maintenance = Arc::new(ManagerArchiveMaintenance { task });
        *existing = Arc::downgrade(&maintenance);
        Ok(maintenance)
    }

    pub(crate) fn require_edge(&self, edge: &Arc<runtime::ArkretEdge>) -> Result<()> {
        if !Arc::ptr_eq(&self.authoring.edge, edge) {
            return Err(BridgeError::Config(
                "manager capability belongs to another host edge".into(),
            ));
        }
        Ok(())
    }

    /// Deployment-only secrets are read by the manager constructor. They are
    /// never added to Config, a Device object or a generic decrypt adapter.
    pub fn open_deployment(edge: Arc<runtime::ArkretEdge>) -> Result<Self> {
        let database = std::env::var_os("ARKRET_MANAGER_ARCHIVE_DATABASE")
            .ok_or_else(|| BridgeError::Config("manager archive database is required".into()))?;
        let key_file = std::env::var_os("ARKRET_MANAGER_ARCHIVE_KEY_FILE")
            .ok_or_else(|| BridgeError::Config("manager archive key file is required".into()))?;
        let key = arkret::KeyBytes::new(std::fs::read(key_file).map_err(|_| {
            BridgeError::Config("cannot read the separate manager archive key file".into())
        })?);
        Self::validate_archive_wrapping_key(&edge, &key)?;
        let database = std::path::absolute(database)
            .map_err(|error| BridgeError::Config(error.to_string()))?;
        let parent = database
            .parent()
            .ok_or_else(|| BridgeError::Config("manager archive database has no parent".into()))?;
        std::fs::create_dir_all(parent).map_err(|error| BridgeError::Config(error.to_string()))?;
        let canonical = if database.exists() {
            database.canonicalize()
        } else {
            let file_name = database.file_name().ok_or_else(|| {
                BridgeError::Config("manager archive database has no file name".into())
            })?;
            parent.canonicalize().map(|parent| parent.join(file_name))
        }
        .map_err(|error| BridgeError::Config(error.to_string()))?;
        let mut vaults = deployment_vaults()
            .lock()
            .map_err(|_| BridgeError::Database("manager vault registry unavailable".into()))?;
        let vault = if let Some(vault) = vaults.get(&canonical).and_then(Weak::upgrade) {
            if !vault.matches_wrapping_key(key.as_slice()) {
                return Err(BridgeError::Config(
                    "manager archive wrapping key differs".into(),
                ));
            }
            vault
        } else {
            let vault = Arc::new(ManagerArchiveVault::open(&canonical, key)?);
            vaults.insert(canonical, Arc::downgrade(&vault));
            vault
        };
        Self::new(edge, vault)
    }

    pub async fn author(&self, request: &AppletManagedActorAuthoringRequest) -> Result<Event> {
        self.authoring.validate_request(request, false).await?;
        // The stable subject includes Realm/Applet and provisioning identity.
        // The actual Actor DID is only computed after this independent public
        // key has entered the inception document and its SCID commitment.
        let subject = managed_actor_subject_key(request)?;
        let vault = self.vault.clone();
        let public =
            crate::run_blocking(move || vault.prepare_candidate_recipient(&subject)).await?;
        self.authoring
            .author_with_archive_key(request, &public)
            .await
    }

    #[cfg(feature = "web")]
    pub fn router(self: &Arc<Self>) -> Router {
        Router::new().push(self.authoring.router()).push(
            Router::with_path("_arkret/edge/applet/managed-actors/author")
                .hoop(crate::web::OperationSelector(
                    arkret::ServiceOperationId::EDGE_APPLET_MANAGED_ACTOR_COMMAND_AUTHOR_V1,
                ))
                .hoop(affix_state::inject(ManagerWebState {
                    service: self.clone(),
                }))
                .post(author_managed_actor),
        )
    }
}
