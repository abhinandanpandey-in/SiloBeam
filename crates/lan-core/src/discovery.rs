use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use thiserror::Error;

pub const SERVICE_TYPE: &str = "_lanpad._tcp.local.";

#[derive(Debug, Error)]
pub enum DiscoveryError {
    #[error("mdns error: {0}")]
    Mdns(#[from] mdns_sd::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredPeer {
    pub device_id: String,
    pub name: String,
    pub addr: String,
    pub port: u16,
}

pub struct LanDiscovery {
    daemon: ServiceDaemon,
}

impl LanDiscovery {
    pub fn new() -> Result<Self, DiscoveryError> {
        Ok(Self {
            daemon: ServiceDaemon::new()?,
        })
    }

    /// Advertise this device on local Wi-Fi via mDNS
    pub fn advertise(
        &self,
        device_id: &str,
        device_name: &str,
        port: u16,
    ) -> Result<(), DiscoveryError> {
        let mut props = HashMap::new();
        props.insert("device_id".to_string(), device_id.to_string());
        props.insert("name".to_string(), device_name.to_string());

        let host = format!("{}.local.", device_id);
        let service = ServiceInfo::new(SERVICE_TYPE, device_id, &host, "", port, props)?
            .enable_addr_auto();

        self.daemon.register(service)?;
        Ok(())
    }

    /// Browse for other LanPad devices on the same LAN
    pub fn browse(&self) -> Result<mdns_sd::Receiver<ServiceEvent>, DiscoveryError> {
        Ok(self.daemon.browse(SERVICE_TYPE)?)
    }

    /// Extract a clean DiscoveredPeer from a resolved mDNS event
    pub fn parse_event(event: ServiceEvent) -> Option<DiscoveredPeer> {
        if let ServiceEvent::ServiceResolved(info) = event {
            let device_id = info.get_property_val_str("device_id")?.to_string();
            let name = info
                .get_property_val_str("name")
                .unwrap_or(&device_id)
                .to_string();

            // Prefer IPv4 address for LAN TCP connections
            let ip: IpAddr = info
                .get_addresses()
                .iter()
                .find(|a| a.is_ipv4())
                .or_else(|| info.get_addresses().iter().next())
                .copied()?;

            return Some(DiscoveredPeer {
                device_id,
                name,
                addr: ip.to_string(),
                port: info.get_port(),
            });
        }
        None
    }
}
