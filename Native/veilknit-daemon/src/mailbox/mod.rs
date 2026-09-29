//! Passive-DHT mailbox protocol and local mailbox controller.
//!
//! The controller is deliberately independent of any one application. It owns
//! the user's Mailbox, MailSend, MailResponse, and overflow DHTs, subscribes to
//! ordinary network-walk observations, and batches copy-on-write page updates.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use futures::{future::BoxFuture, stream, StreamExt};
use rand_core::{OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet, VecDeque},
    fmt,
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{broadcast, mpsc, oneshot, watch, RwLock},
    time::{self, MissedTickBehavior},
};
use veilid_core::{Crypto, KeyPair, PublicKey, RecordKey, RouteId, Signature, VeilidAPI, CRYPTO_KIND_VLD0};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

use crate::{
    dht_module::{CreateDhtError, DHTModule},
    identity_manager::{AppCapability, AuthenticatedAppSession},
    reputation::{
        AccessLevel, AppId, ObservationDetails, ObservationInput, ObservationKind,
        ReputationModuleHandle,
    },
    types::{
        current_timestamp, MailboxAdvertisement, ReceiveKeyStatus, ReceiveKeyVersion,
        MAILBOX_ADVERTISEMENT_LOCATION,
    },
    user_auth::{AuthError, UserAuth, UserSession},
    walk_task::{HopDirective, HopEvent, WalkRunReport, WalkSubscriber},
};

include!("config.rs");
include!("protocol.rs");
include!("persistence.rs");
include!("page_store.rs");
include!("quota.rs");
include!("crypto.rs");
include!("controller_api.rs");
include!("runtime.rs");
include!("outbox.rs");
include!("walk_integration.rs");
include!("maintenance.rs");
include!("tests.rs");
