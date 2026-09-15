use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::dto::*;
use super::error::{ErrorCode, OperatorRulesError as Error};
use crate::config::custom_list::grammar::compose_line;
use crate::config::loader::LoadedConfigV5;
use crate::config::policy_revision::{
    PolicyMemberKind as Kind, PolicyMemberState, PolicyRevisionInventory as Inventory,
    PolicyRevisionMember as Member, PolicyRevisionSnapshot,
};
use crate::config::schema::Id;
use crate::filter::operator_rules::parse_rule_ast;

pub(crate) fn digest(bytes: &[u8]) -> String {
    hex_key(Sha256::digest(bytes).into())
}

fn row_text(raw: &str) -> &str {
    raw.strip_suffix('\n')
        .unwrap_or(raw)
        .strip_suffix('\r')
        .unwrap_or_else(|| raw.strip_suffix('\n').unwrap_or(raw))
}

fn row_parts(raw: &str) -> (Option<RuleAction>, Option<[u8; 32]>, bool) {
    let text = row_text(raw);
    if text.trim().is_empty() || text.trim_start().starts_with('#') {
        return (None, None, true);
    }
    match parse_rule_ast(text) {
        Ok(ast) => (
            Some(if ast.tier().is_allow() {
                RuleAction::Allow
            } else {
                RuleAction::Deny
            }),
            Some(ast.rule_key().0),
            true,
        ),
        Err(_) => (None, None, false),
    }
}

pub(crate) fn pack_counts(body: &str) -> (usize, usize) {
    body.split_inclusive('\n')
        .fold((0, 0), |(rules, invalid), raw| {
            let (action, _, valid) = row_parts(raw);
            (
                rules + usize::from(action.is_some()),
                invalid + usize::from(!valid),
            )
        })
}

pub(crate) struct RowPage {
    pub rows: Vec<RuleRow>,
    pub total: usize,
}

pub(crate) fn row_page(id: &str, body: &str, offset: usize, limit: usize) -> RowPage {
    let revision = digest(body.as_bytes());
    let mut seen = BTreeSet::<[u8; 32]>::new();
    let mut selected = Vec::with_capacity(limit.min(512));
    let mut total = 0;
    for (index, raw) in body.split_inclusive('\n').enumerate() {
        let (action, key, valid) = row_parts(raw);
        let duplicate = key.is_some_and(|key| !seen.insert(key));
        if index >= offset && selected.len() < limit {
            selected.push(RuleRow {
                line: index + 1,
                raw: row_text(raw).to_string(),
                row_ref: format!("{id}:{revision}:{}:{}", index + 1, digest(raw.as_bytes())),
                rule_key: key.map(hex_key),
                action,
                valid,
                duplicate,
            });
        }
        total = index + 1;
    }
    RowPage {
        rows: selected,
        total,
    }
}

fn hex_key(bytes: [u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn valid_id(id: &str) -> Result<(), Error> {
    Id::new(id)
        .map(|_| ())
        .map_err(|e| Error::new(ErrorCode::InvalidId, e.to_string()))
}

pub(crate) fn validate_request(
    request: &BatchRequest,
    limits: TransportLimits,
) -> Result<(), Error> {
    if request.contract_version != CONTRACT_VERSION {
        return Err(Error::new(
            ErrorCode::UnsupportedContract,
            "supported contract_version is 1",
        ));
    }
    if request.request_id.is_empty()
        || request.request_id.len() > 128
        || request.request_id.chars().any(char::is_control)
    {
        return Err(Error::new(
            ErrorCode::InvalidRequest,
            "request_id must contain 1–128 non-control bytes",
        ));
    }
    if request.operations.is_empty() {
        return Err(Error::new(
            ErrorCode::InvalidRequest,
            "operations must not be empty",
        ));
    }
    if request.operations.len() > limits.max_operations || request.operations.len() > 256 {
        return Err(Error::new(
            ErrorCode::TransportLimitExceeded,
            "batch exceeds transport operation limit; use REST for larger atomic batches",
        ));
    }
    if request.expected_config_revision.len() != 64
        || !request
            .expected_config_revision
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(Error::new(
            ErrorCode::InvalidRequest,
            "expected_config_revision must be a SHA-256 digest",
        ));
    }
    for operation in &request.operations {
        match operation {
            Operation::AddRawRule { rule, .. } | Operation::ReplaceRule { rule, .. } => {
                canonical_rule(rule)?;
            }
            Operation::AddDomainRule { domain, action, .. } => {
                compose_line(domain, *action == RuleAction::Allow)
                    .map_err(|e| Error::new(ErrorCode::InvalidRule, e.to_string()))?;
            }
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn canonicalize_request(request: &BatchRequest) -> Result<BatchRequest, Error> {
    let mut canonical = request.clone();
    for operation in &mut canonical.operations {
        match operation {
            Operation::AddDomainRule { domain, .. } => *domain = domain.to_ascii_lowercase(),
            Operation::AddRawRule { rule, .. } | Operation::ReplaceRule { rule, .. } => {
                *rule = canonical_rule(rule)?
            }
            _ => {}
        }
    }
    Ok(canonical)
}

pub(crate) fn primary_only(loaded: &LoadedConfigV5) -> Result<(), Error> {
    if loaded.config.cluster.enabled
        && loaded.config.cluster.role == crate::config::schema::ClusterRole::Secondary
    {
        return Err(Error::new(
            ErrorCode::PolicyOwnedByPrimary,
            "operator policy is owned by the primary, including offline operations",
        ));
    }
    Ok(())
}

fn canonical_rule(rule: &str) -> Result<String, Error> {
    if rule
        .chars()
        .any(|c| c.is_control() || matches!(c, '\u{85}' | '\u{2028}' | '\u{2029}'))
    {
        return Err(Error::new(
            ErrorCode::InvalidRule,
            "rule must contain exactly one record without control characters",
        ));
    }
    parse_rule_ast(rule).map_err(|e| Error::new(ErrorCode::InvalidRule, e.to_string()))?;
    Ok(rule.trim().to_string())
}

pub(crate) struct Candidate {
    pub plan: Plan,
    pub inventory: Inventory,
}

struct PackEdit {
    revision: String,
    original: String,
    replacements: BTreeMap<usize, String>,
    deletions: BTreeSet<usize>,
    appended: Vec<String>,
    edited_original_rows: BTreeSet<usize>,
}

impl PackEdit {
    fn new(original: &str) -> Self {
        Self {
            revision: digest(original.as_bytes()),
            original: original.to_string(),
            replacements: BTreeMap::new(),
            deletions: BTreeSet::new(),
            appended: Vec::new(),
            edited_original_rows: BTreeSet::new(),
        }
    }

    fn resolve_original_ref(&self, id: &str, row_ref: &str) -> Result<usize, Error> {
        let prefix = format!("{id}:{}:", self.revision);
        let remainder = row_ref.strip_prefix(&prefix).ok_or_else(row_conflict)?;
        let (line, expected_digest) = remainder.rsplit_once(':').ok_or_else(row_conflict)?;
        if expected_digest.len() != 64
            || !expected_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(row_conflict());
        }
        let line = line.parse::<usize>().map_err(|_| row_conflict())?;
        if line == 0 {
            return Err(row_conflict());
        }
        let raw = self
            .original
            .split_inclusive('\n')
            .nth(line - 1)
            .ok_or_else(row_conflict)?;
        if digest(raw.as_bytes()) != expected_digest {
            return Err(row_conflict());
        }
        Ok(line)
    }

    fn begin_original_edit(&mut self, id: &str, row_ref: &str) -> Result<usize, Error> {
        let line = self.resolve_original_ref(id, row_ref)?;
        if !self.edited_original_rows.insert(line) {
            return Err(Error::new(
                ErrorCode::RowConflict,
                "the same original row cannot be edited twice in one batch",
            ));
        }
        Ok(line)
    }

    fn original_raw(&self, line: usize) -> Result<&str, Error> {
        self.original
            .split_inclusive('\n')
            .nth(line - 1)
            .ok_or_else(row_conflict)
    }

    fn contains_key(&self, expected: [u8; 32]) -> bool {
        self.effective_rows()
            .any(|raw| row_parts(raw).1.is_some_and(|key| key == expected))
    }

    fn effective_rows(&self) -> impl Iterator<Item = &str> {
        let original =
            self.original
                .split_inclusive('\n')
                .enumerate()
                .filter_map(|(index, raw)| {
                    let line = index + 1;
                    if self.deletions.contains(&line) {
                        None
                    } else {
                        Some(self.replacements.get(&line).map_or(raw, String::as_str))
                    }
                });
        original.chain(self.appended.iter().map(String::as_str))
    }

    fn render(self) -> String {
        let mut body = String::with_capacity(
            self.original.len() + self.appended.iter().map(String::len).sum::<usize>(),
        );
        for raw in self.effective_rows() {
            body.push_str(raw);
        }
        body
    }
}

fn row_conflict() -> Error {
    Error::new(
        ErrorCode::RowConflict,
        "row reference is stale or does not belong to this pack",
    )
}

pub(crate) fn build(
    request: &BatchRequest,
    snapshot: &PolicyRevisionSnapshot,
    loaded: &LoadedConfigV5,
    limits: TransportLimits,
) -> Result<Candidate, Error> {
    validate_request(request, limits)?;
    primary_only(loaded)?;
    if request.expected_config_revision != snapshot.revision().to_string() {
        return Err(Error::new(
            ErrorCode::RevisionConflict,
            "configuration changed; read and plan again",
        ));
    }
    let mut docs = BTreeMap::<PathBuf, (Kind, toml::Value)>::new();
    let mut packs = BTreeMap::<String, PackEdit>::new();
    let mut original = BTreeMap::new();
    let mut master = PathBuf::new();
    for member in snapshot.inventory().members() {
        let PolicyMemberState::Present(bytes) = member.state() else {
            continue;
        };
        original.insert(member.path().to_path_buf(), bytes.clone());
        let text = std::str::from_utf8(bytes).map_err(Error::storage)?;
        if member.kind() == Kind::Pack {
            let id = member
                .path()
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| Error::new(ErrorCode::UnsafePath, "invalid pack path"))?;
            packs.insert(id.to_string(), PackEdit::new(text));
        } else {
            if member.kind() == Kind::Master {
                master = member.path().to_path_buf();
            }
            docs.insert(
                member.path().to_path_buf(),
                (member.kind(), toml::from_str(text).map_err(Error::storage)?),
            );
        }
    }
    let original_docs = docs.clone();
    let before_mounts = profile_mounts(&original_docs)?;
    for operation in &request.operations {
        let id = match operation {
            Operation::CreateList { id, .. }
            | Operation::SetMetadata { id, .. }
            | Operation::AddDomainRule { id, .. }
            | Operation::AddRawRule { id, .. }
            | Operation::ReplaceRule { id, .. }
            | Operation::RemoveRule { id, .. }
            | Operation::Mount { id, .. }
            | Operation::Unmount { id, .. }
            | Operation::DeleteList { id, .. } => id,
        };
        valid_id(id)?;
        let declaration_path = docs
            .iter()
            .find(|(_, (_, doc))| {
                entries(doc)
                    .iter()
                    .any(|row| row.get("id").and_then(toml::Value::as_str) == Some(id))
            })
            .map(|(path, _)| path.clone());
        if !matches!(operation, Operation::CreateList { .. }) && declaration_path.is_none() {
            return Err(Error::new(
                ErrorCode::NotFound,
                format!("custom list {id} does not exist"),
            ));
        }
        match operation {
            Operation::CreateList {
                display_name,
                description,
                into,
                ..
            } => {
                if declaration_path.is_some()
                    || snapshot
                        .orphan_packs()
                        .iter()
                        .any(|path| path == Path::new(&format!("packs/{id}.txt")))
                {
                    return Err(Error::new(
                        ErrorCode::AlreadyExists,
                        format!("custom list or orphan pack {id} already exists"),
                    ));
                }
                let path = into.as_ref().map_or_else(|| master.clone(), PathBuf::from);
                if path.is_absolute()
                    || path
                        .components()
                        .any(|part| !matches!(part, std::path::Component::Normal(_)))
                {
                    return Err(Error::new(
                        ErrorCode::UnsafePath,
                        "into must be a canonical relative member path",
                    ));
                }
                if !docs.contains_key(&path) {
                    if path.extension().and_then(|s| s.to_str()) != Some("toml") {
                        return Err(Error::new(
                            ErrorCode::UnsafePath,
                            "into must name a relative TOML member",
                        ));
                    }
                    docs.insert(
                        path.clone(),
                        (Kind::Include, toml::Value::Table(toml::map::Map::new())),
                    );
                }
                let doc = &mut docs.get_mut(&path).unwrap().1;
                let mut row = toml::map::Map::new();
                row.insert("id".into(), id.clone().into());
                row.insert("display_name".into(), display_name.clone().into());
                row.insert("description".into(), description.clone().into());
                doc.as_table_mut()
                    .unwrap()
                    .entry("custom_lists")
                    .or_insert_with(|| toml::Value::Array(vec![]))
                    .as_array_mut()
                    .ok_or_else(|| {
                        Error::new(ErrorCode::ValidationFailed, "custom_lists is not an array")
                    })?
                    .push(toml::Value::Table(row));
                packs.insert(id.clone(), PackEdit::new(""));
            }
            Operation::SetMetadata {
                display_name,
                description,
                ..
            } => {
                let doc = &mut docs.get_mut(&declaration_path.unwrap()).unwrap().1;
                let row = doc
                    .get_mut("custom_lists")
                    .unwrap()
                    .as_array_mut()
                    .unwrap()
                    .iter_mut()
                    .find(|row| row.get("id").and_then(toml::Value::as_str) == Some(id))
                    .unwrap()
                    .as_table_mut()
                    .unwrap();
                if let Some(value) = display_name {
                    row.insert("display_name".into(), value.clone().into());
                }
                if let Some(value) = description {
                    row.insert("description".into(), value.clone().into());
                }
            }
            Operation::AddDomainRule { domain, action, .. } => {
                let line = compose_line(domain, *action == RuleAction::Allow)
                    .map_err(|e| Error::new(ErrorCode::InvalidRule, e.to_string()))?;
                append_rule(packs.get_mut(id).unwrap(), &line)?;
            }
            Operation::AddRawRule { rule, .. } => {
                append_rule(packs.get_mut(id).unwrap(), &canonical_rule(rule)?)?;
            }
            Operation::ReplaceRule { row_ref, rule, .. } => {
                let rule = canonical_rule(rule)?;
                let pack = packs.get_mut(id).unwrap();
                let line = pack.begin_original_edit(id, row_ref)?;
                let original = pack.original_raw(line)?;
                if parse_rule_ast(row_text(original)).ok() != parse_rule_ast(&rule).ok() {
                    let ending = if original.ends_with("\r\n") {
                        "\r\n"
                    } else if original.ends_with('\n') {
                        "\n"
                    } else {
                        ""
                    };
                    pack.replacements.insert(line, format!("{rule}{ending}"));
                }
            }
            Operation::RemoveRule { row_ref, .. } => {
                let pack = packs.get_mut(id).unwrap();
                let line = pack.begin_original_edit(id, row_ref)?;
                pack.deletions.insert(line);
            }
            Operation::Mount { profile_id, .. } | Operation::Unmount { profile_id, .. } => {
                valid_id(profile_id)?;
                let profile = docs
                    .values_mut()
                    .find_map(|(_, doc)| {
                        doc.get_mut("profiles").and_then(|p| p.get_mut(profile_id))
                    })
                    .ok_or_else(|| {
                        Error::new(
                            ErrorCode::NotFound,
                            format!("profile {profile_id} does not exist"),
                        )
                    })?;
                patch_mount(profile, id, matches!(operation, Operation::Mount { .. }))?;
            }
            Operation::DeleteList {
                cascade_unmount, ..
            } => {
                for (_, doc) in docs.values_mut() {
                    if let Some(profiles) =
                        doc.get_mut("profiles").and_then(toml::Value::as_table_mut)
                    {
                        for (profile_id, profile) in profiles {
                            if mounted(profile, id) {
                                if !cascade_unmount {
                                    return Err(Error::new(ErrorCode::ListMounted, format!("custom list {id} is mounted by {profile_id}; use cascade_unmount")));
                                }
                                patch_mount(profile, id, false)?;
                            }
                        }
                    }
                }
                docs.get_mut(&declaration_path.unwrap())
                    .unwrap()
                    .1
                    .get_mut("custom_lists")
                    .unwrap()
                    .as_array_mut()
                    .unwrap()
                    .retain(|row| row.get("id").and_then(toml::Value::as_str) != Some(id));
                packs.remove(id);
            }
        }
    }
    let after_mounts = profile_mounts(&docs)?;
    let mut members = vec![];
    for (path, (kind, value)) in docs {
        let bytes = if original_docs
            .get(&path)
            .is_some_and(|(_, old)| old == &value)
        {
            original[&path].clone()
        } else {
            crate::config::toml_write::render_preserving(
                std::str::from_utf8(original.get(&path).map_or(&[], Vec::as_slice))
                    .map_err(Error::storage)?,
                &value,
            )
            .map_err(Error::storage)?
            .into_bytes()
        };
        members.push(Member::present(kind, path, bytes).map_err(Error::storage)?);
    }
    let mut pack_bytes_after = 0;
    let mut rules_after = 0;
    let mut warnings = vec![];
    let mut content_changed_lists = BTreeSet::new();
    for (id, pack) in packs {
        let body = pack.render();
        if body.len() > loaded.config.custom_list_limits.max_file_bytes {
            return Err(Error::new(
                ErrorCode::BudgetExceeded,
                format!("pack {id} exceeds max_file_bytes"),
            ));
        }
        pack_bytes_after += body.len();
        let (pack_rules, invalid_rows, duplicates) = analyze_pack(&body);
        rules_after += pack_rules;
        if invalid_rows != 0 {
            warnings.push(format!(
                "{id}: invalid rows require correction before schema-5 activation"
            ));
        }
        if duplicates {
            warnings.push(format!("{id}: duplicate rule occurrences retained"));
        }
        let path = PathBuf::from(format!("packs/{id}.txt"));
        if original.get(&path).map(Vec::as_slice) != Some(body.as_bytes()) {
            content_changed_lists.insert(id.clone());
        }
        members.push(Member::present(Kind::Pack, path, body.into_bytes()).map_err(Error::storage)?);
    }
    let mut impacted = BTreeSet::new();
    for profile_id in before_mounts.keys().chain(after_mounts.keys()) {
        let before = before_mounts.get(profile_id);
        let after = after_mounts.get(profile_id);
        if before != after
            || after
                .or(before)
                .is_some_and(|mounts| !mounts.is_disjoint(&content_changed_lists))
        {
            impacted.insert(profile_id.clone());
        }
    }
    let inventory = Inventory::new(members).map_err(Error::storage)?;
    let mut touched = BTreeSet::new();
    for member in inventory.members() {
        if let PolicyMemberState::Present(bytes) = member.state() {
            if original.get(member.path()) != Some(bytes) {
                touched.insert(member.path().display().to_string());
            }
        }
    }
    for path in original.keys() {
        if !inventory
            .members()
            .iter()
            .any(|member| member.path() == path)
        {
            touched.insert(path.display().to_string());
        }
    }
    let mut recipients = BTreeSet::new();
    for device in &loaded.config.devices {
        if device
            .profile
            .as_ref()
            .is_some_and(|id| impacted.contains(id.as_str()))
        {
            recipients.insert(format!("device:{}", device.id));
        }
    }
    for group in &loaded.config.groups {
        if impacted.contains(group.profile.as_str()) {
            recipients.insert(format!("group:{}", group.id));
            for id in &group.devices {
                recipients.insert(format!("device:{id}"));
            }
            for device in &loaded.config.devices {
                if device.groups.contains(&group.id) {
                    recipients.insert(format!("device:{}", device.id));
                }
            }
        }
    }
    for subnet in &loaded.config.subnets {
        if impacted.contains(subnet.profile.as_str()) {
            recipients.insert(format!("subnet:{}", subnet.id));
        }
    }
    for schedule in &loaded.config.schedules {
        if impacted.contains(schedule.profile.as_str()) {
            recipients.insert(format!("schedule:{}", schedule.id));
            match schedule.target_type {
                crate::config::schema::ScheduleTargetType::Device => {
                    recipients.insert(format!("device:{}", schedule.target_id));
                }
                crate::config::schema::ScheduleTargetType::Group => {
                    recipients.insert(format!("group:{}", schedule.target_id));
                    if let Some(group) = loaded
                        .config
                        .groups
                        .iter()
                        .find(|group| group.id == schedule.target_id)
                    {
                        for id in &group.devices {
                            recipients.insert(format!("device:{id}"));
                        }
                    }
                    for device in &loaded.config.devices {
                        if device.groups.contains(&schedule.target_id) {
                            recipients.insert(format!("device:{}", device.id));
                        }
                    }
                }
            }
        }
    }
    if loaded
        .config
        .server
        .default_profile
        .as_ref()
        .is_some_and(|id| impacted.contains(id.as_str()))
    {
        recipients.insert("default:unknown-clients".into());
    }
    let mut canonical = canonicalize_request(request)?;
    canonical.expected_plan_hash = None;
    let plan = Plan {
        contract_version: 1,
        planner_version: 3,
        request: canonical,
        base_config_revision: snapshot.revision().to_string(),
        candidate_config_revision: inventory.revision().to_string(),
        base_operator_policy_hash: String::new(),
        candidate_operator_policy_hash: String::new(),
        semantic_diff: SemanticDiffSummary::default(),
        plan_hash: String::new(),
        changed: !touched.is_empty(),
        touched_members: touched.into_iter().collect(),
        impacted_profiles: impacted.into_iter().collect(),
        impacted_recipients: recipients.into_iter().collect(),
        pack_bytes_after,
        rules_after,
        warnings,
        required_capabilities: vec!["operator-rule-grammar-1".into(), "semantic-hash-v1".into()],
    };
    Ok(Candidate { plan, inventory })
}

pub(crate) fn attach_semantic(
    plan: &mut Plan,
    semantic: &super::semantic::SemanticDiff,
    expected_plan_hash: Option<&str>,
) -> Result<(), Error> {
    plan.base_operator_policy_hash = semantic.before.to_string();
    plan.candidate_operator_policy_hash = semantic.after.to_string();
    plan.semantic_diff = SemanticDiffSummary {
        semantic_changed: semantic.semantic_changed,
        cosmetic_changed: semantic.cosmetic_changed,
        rules_added: semantic
            .rule_deltas
            .iter()
            .filter(|delta| delta.kind == super::semantic::RuleDeltaKind::Added)
            .count(),
        rules_removed: semantic
            .rule_deltas
            .iter()
            .filter(|delta| delta.kind == super::semantic::RuleDeltaKind::Removed)
            .count(),
        exact_changes: semantic
            .rule_deltas
            .iter()
            .filter(|delta| delta.class == super::semantic::RuleClass::Exact)
            .count(),
        wildcard_changes: semantic
            .rule_deltas
            .iter()
            .filter(|delta| delta.class == super::semantic::RuleClass::Wildcard)
            .count(),
        regex_changes: semantic
            .rule_deltas
            .iter()
            .filter(|delta| delta.class == super::semantic::RuleClass::Regex)
            .count(),
        changed_scopes: semantic
            .semantic_entries
            .iter()
            .map(|entry| entry.scope.clone())
            .collect(),
        omitted_entries: semantic.omitted_entries,
    };
    plan.plan_hash.clear();
    let encoded = serde_json::to_vec(&plan).map_err(Error::storage)?;
    let mut bytes = b"warden/uor/public-plan/v1\0".to_vec();
    bytes.extend_from_slice(&(encoded.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&encoded);
    plan.plan_hash = digest(&bytes);
    if expected_plan_hash.is_some_and(|hash| hash != plan.plan_hash) {
        return Err(Error::new(
            ErrorCode::PlanConflict,
            "plan hash differs from the requested candidate",
        ));
    }
    Ok(())
}

fn entries(doc: &toml::Value) -> &[toml::Value] {
    doc.get("custom_lists")
        .and_then(toml::Value::as_array)
        .map_or(&[], Vec::as_slice)
}

fn profile_mounts(
    docs: &BTreeMap<PathBuf, (Kind, toml::Value)>,
) -> Result<BTreeMap<String, BTreeSet<String>>, Error> {
    let mut result = BTreeMap::new();
    for (_, doc) in docs.values() {
        let Some(profiles) = doc.get("profiles") else {
            continue;
        };
        let profiles = profiles
            .as_table()
            .ok_or_else(|| Error::new(ErrorCode::ValidationFailed, "profiles is not a table"))?;
        for (profile_id, profile) in profiles {
            let mut mounts = BTreeSet::new();
            if let Some(values) = profile.get("custom_lists") {
                let values = values.as_array().ok_or_else(|| {
                    Error::new(
                        ErrorCode::ValidationFailed,
                        "custom_lists mount is not an array",
                    )
                })?;
                for value in values {
                    let id = value.as_str().ok_or_else(|| {
                        Error::new(
                            ErrorCode::ValidationFailed,
                            "custom_lists contains a non-string mount",
                        )
                    })?;
                    mounts.insert(id.to_string());
                }
            }
            if result.insert(profile_id.clone(), mounts).is_some() {
                return Err(Error::new(
                    ErrorCode::ValidationFailed,
                    format!("profile {profile_id} is declared more than once"),
                ));
            }
        }
    }
    Ok(result)
}

fn mounted(profile: &toml::Value, id: &str) -> bool {
    profile
        .get("custom_lists")
        .and_then(toml::Value::as_array)
        .is_some_and(|mounts| mounts.iter().any(|mount| mount.as_str() == Some(id)))
}
fn patch_mount(profile: &mut toml::Value, id: &str, add: bool) -> Result<bool, Error> {
    if profile
        .get("custom_lists")
        .and_then(toml::Value::as_array)
        .is_some_and(|mounts| mounts.iter().any(|value| value.as_str().is_none()))
    {
        return Err(Error::new(
            ErrorCode::ValidationFailed,
            "custom_lists contains a non-string mount",
        ));
    }
    if mounted(profile, id) == add {
        return Ok(false);
    }
    let mounts = profile
        .as_table_mut()
        .ok_or_else(|| Error::new(ErrorCode::ValidationFailed, "profile is not a table"))?
        .entry("custom_lists")
        .or_insert_with(|| toml::Value::Array(vec![]))
        .as_array_mut()
        .ok_or_else(|| {
            Error::new(
                ErrorCode::ValidationFailed,
                "custom_lists mount is not an array",
            )
        })?;
    if add {
        mounts.push(id.to_string().into());
    } else {
        mounts.retain(|value| value.as_str() != Some(id));
    }
    if mounts.is_empty() {
        profile.as_table_mut().unwrap().remove("custom_lists");
    }
    Ok(true)
}
fn analyze_pack(body: &str) -> (usize, usize, bool) {
    let mut rules = 0;
    let mut invalid = 0;
    let mut duplicate = false;
    let mut seen = BTreeSet::<[u8; 32]>::new();
    for raw in body.split_inclusive('\n') {
        let (action, key, valid) = row_parts(raw);
        rules += usize::from(action.is_some());
        invalid += usize::from(!valid);
        duplicate |= key.is_some_and(|key| !seen.insert(key));
    }
    (rules, invalid, duplicate)
}

fn append_rule(pack: &mut PackEdit, rule: &str) -> Result<bool, Error> {
    let key = parse_rule_ast(rule)
        .map_err(|e| Error::new(ErrorCode::InvalidRule, e.to_string()))?
        .rule_key()
        .0;
    if pack.contains_key(key) {
        return Ok(false);
    }
    if pack
        .effective_rows()
        .last()
        .is_some_and(|last| !last.ends_with('\n'))
    {
        pack.appended.push("\n".into());
    }
    pack.appended.push(format!("{rule}\n"));
    Ok(true)
}
