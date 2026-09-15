//! Schema-4 cluster bundles are retired.
//!
//! The live cluster path carries only an artifact-format-2 schema-5 policy
//! through [`super::artifact`]. Schema-4 decoding remains in the dedicated
//! migration subsystem and is intentionally not re-exported here.
