use base64::Engine;
use serde::de::DeserializeOwned;
use serde::Serialize;

use purge_warden::ipc::protocol::{IpcCommand, IpcResponse};
use purge_warden::operator_rules::{
    Capabilities, OperatorRulesService, PageRequest, Plan, Receipt, TransportLimits,
    CONTRACT_VERSION,
};

const CAPABILITIES: &str = include_str!("fixtures/uor8-contract-v1/capabilities.json");
const PLAN: &str = include_str!("fixtures/uor8-contract-v1/plan.json");
const APPLY: &str = include_str!("fixtures/uor8-contract-v1/apply.json");
const RECEIPT: &str = include_str!("fixtures/uor8-contract-v1/receipt.json");
const PAGE_CURSOR: &str = include_str!("fixtures/uor8-contract-v1/page-cursor.json");
const ERROR: &str = include_str!("fixtures/uor8-contract-v1/error.json");

fn assert_golden<T>(fixture: &str)
where
    T: DeserializeOwned + Serialize,
{
    let decoded: T = serde_json::from_str(fixture).expect("fixture must deserialize");
    assert_eq!(
        serde_json::to_string_pretty(&decoded).expect("DTO must serialize"),
        fixture.trim_end(),
        "fixture must remain the stable serialized shape"
    );
}

#[test]
fn uor_v1_json_goldens_preserve_public_contract_shapes() {
    assert_eq!(CONTRACT_VERSION, 1);

    let mut capabilities: Capabilities = serde_json::from_str(CAPABILITIES).unwrap();
    capabilities.cluster_artifact = cfg!(feature = "cluster");
    assert_eq!(
        capabilities,
        OperatorRulesService::new("unused-config-path").capabilities(TransportLimits::REST)
    );
    assert_golden::<Capabilities>(CAPABILITIES);
    assert_golden::<Plan>(PLAN);
    assert_golden::<IpcCommand>(APPLY);
    assert_golden::<Receipt>(RECEIPT);
    assert_golden::<IpcResponse>(ERROR);

    let page_cursor: serde_json::Value = serde_json::from_str(PAGE_CURSOR).unwrap();
    let request: PageRequest =
        serde_json::from_value(page_cursor["cursor_request"].clone()).unwrap();
    let page: purge_warden::operator_rules::RulePage =
        serde_json::from_value(page_cursor["page"].clone()).unwrap();
    assert_eq!(request.limit, Some(50));
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(request.cursor.as_deref().unwrap())
            .unwrap(),
        format!(
            "{}:{}\nlocal-rules\n2",
            page.config_revision, page.pack_revision
        )
        .into_bytes()
    );
    assert_eq!(page.contract_version, CONTRACT_VERSION);
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(page.next_cursor.as_deref().unwrap())
            .unwrap(),
        format!(
            "{}:{}\nlocal-rules\n3",
            page.config_revision, page.pack_revision
        )
        .into_bytes()
    );
    assert_eq!(
        serde_json::to_value(request).unwrap(),
        page_cursor["cursor_request"],
        "cursor request shape must remain stable"
    );
    assert_eq!(
        serde_json::to_value(page).unwrap(),
        page_cursor["page"],
        "page shape must remain stable"
    );
}
