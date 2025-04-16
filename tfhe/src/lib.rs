//! Welcome to the TFHE-rs API documentation!
//!
//! TFHE-rs is a fully homomorphic encryption (FHE) library that implements Zama's variant of TFHE.

// Enable all warnings in doctests
// https://doc.rust-lang.org/rustdoc/write-documentation/documentation-tests.html#showing-warnings-in-doctests
#![doc(test(attr(warn(unused))))]
#![doc(test(attr(allow(unused_variables))))]
#![doc(test(attr(allow(unused_imports))))]
// Enable all warnings first as it may break the "allow" priority/activation as some lints gets
// moved around in clippy categories

// Enable pedantic lints
#![warn(clippy::pedantic)]
// Nursery lints
#![warn(clippy::nursery)]
#![warn(rustdoc::broken_intra_doc_links)]
// The following lints have been temporarily allowed
// They are expected to be fixed progressively
#![allow(clippy::unreadable_literal)] // 830
#![allow(clippy::doc_markdown)] // 688
#![allow(clippy::missing_panics_doc)] // 667
#![allow(clippy::cast_possible_truncation)] // 540
#![allow(clippy::similar_names)] // 514
#![allow(clippy::must_use_candidate)] // 356
#![allow(clippy::wildcard_imports)] // 350
#![allow(clippy::module_name_repetitions)] // 328
#![allow(clippy::cast_lossless)] // 280
#![allow(clippy::missing_const_for_fn)] // 243
#![allow(clippy::missing_errors_doc)] // 118
#![allow(clippy::cast_precision_loss)] // 102
#![allow(clippy::items_after_statements)] // 99
#![allow(clippy::cast_sign_loss)] // 97
#![allow(clippy::inline_always)] // 51
#![allow(clippy::many_single_char_names)] // 44
#![allow(clippy::too_many_lines)] // 34
#![allow(clippy::match_same_arms)] // 19
#![allow(clippy::range_plus_one)] // 16
#![allow(clippy::return_self_not_must_use)] // 11
#![allow(clippy::ignored_unit_patterns)] // 9
#![allow(clippy::large_types_passed_by_value)] // 8
#![allow(clippy::float_cmp)] // 7
#![allow(clippy::bool_to_int_with_if)] // 6
#![allow(clippy::unsafe_derive_deserialize)] // 1
#![allow(clippy::cast_possible_wrap)] // 1
#![allow(clippy::too_long_first_doc_paragraph)]
#![allow(clippy::redundant_closure_for_method_calls)]
// These pedantic lints are deemed to bring too little value therefore they are allowed (which are
// their natural state anyways, being pedantic lints)

// Would require a ; for the last statement of a function even if the function returns (), compiler
// indicates it is for formatting consistency, cargo fmt works well with it allowed anyways.
#![allow(clippy::semicolon_if_nothing_returned)]
// Warns when iter or iter_mut are called explicitly, but it reads more nicely e.g. when there are
// parallel and sequential iterators that are mixed
#![allow(clippy::explicit_iter_loop)]
// End allowed pedantic lints

// The following lints have been temporarily allowed
// They are expected to be fixed progressively
#![allow(clippy::missing_const_for_fn)] // 243
#![allow(clippy::redundant_pub_crate)] // 116
#![allow(clippy::suboptimal_flops)] // 43
#![allow(clippy::significant_drop_tightening)] // 10
#![allow(clippy::cognitive_complexity)] // 6
#![allow(clippy::iter_with_drain)] // 2
#![allow(clippy::large_stack_frames)] // 1
#![cfg_attr(feature = "__wasm_api", allow(dead_code))]
#![cfg_attr(
    all(
        any(target_arch = "x86", target_arch = "x86_64"),
        feature = "nightly-avx512"
    ),
    feature(avx512_target_feature, stdarch_x86_avx512)
)]
#![cfg_attr(all(doc, not(doctest)), feature(doc_auto_cfg))]
#![cfg_attr(all(doc, not(doctest)), feature(doc_cfg))]
// Weird clippy lint triggering without any code location
#![cfg_attr(test, allow(clippy::large_stack_arrays))]

#[cfg(feature = "__c_api")]
pub mod c_api;

#[cfg(feature = "boolean")]
/// Welcome to the TFHE-rs [`boolean`](`crate::boolean`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod boolean;

/// Welcome to the TFHE-rs [`core_crypto`](`crate::core_crypto`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod core_crypto;

#[cfg(feature = "integer")]
/// Welcome to the TFHE-rs [`integer`](`crate::integer`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod integer;

#[cfg(feature = "shortint")]
/// Welcome to the TFHE-rs [`shortint`](`crate::shortint`) module documentation!
///
/// # Special module attributes
/// cbindgen:ignore
pub mod shortint;

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

use petgraph::{
    algo::toposort,
    prelude::{NodeIndex, StableGraph},
    visit::{EdgeRef, NodeRef},
    Direction,
};
#[cfg(feature = "pbs-stats")]
pub use shortint::server_key::pbs_stats::*;

#[cfg(feature = "__wasm_api")]
/// cbindgen:ignore
mod js_on_wasm_api;

#[cfg(all(
    doctest,
    feature = "shortint",
    feature = "boolean",
    feature = "integer",
    feature = "zk-pok",
    feature = "strings"
))]
mod test_user_docs;

#[cfg(feature = "strings")]
pub mod strings;

#[cfg(feature = "integer")]
/// cbindgen:ignore
pub(crate) mod high_level_api;

#[cfg(feature = "integer")]
pub use high_level_api::*;

#[cfg(any(test, doctest, feature = "internal-keycache"))]
/// cbindgen:ignore
pub mod keycache;

pub mod safe_serialization;

pub mod conformance;

pub mod named;

pub mod error;
#[cfg(feature = "zk-pok")]
pub mod zk;

#[cfg(any(feature = "integer", feature = "shortint"))]
pub(crate) use error::error;
pub use error::{Error, ErrorKind};
pub type Result<T> = std::result::Result<T, Error>;

pub use tfhe_versionable::{Unversionize, Versionize};

pub struct TraceCtx {
    graph: StableGraph<FheOp, ()>,
    id_map: HashMap<usize, NodeIndex>,
}

impl TraceCtx {
    pub fn pbs_critical_path(&self) -> usize {
        let mut pbs_depth = HashMap::<NodeIndex, usize>::new();

        let nodes = toposort(&self.graph, None).unwrap();

        for n in nodes {
            let mut max_depth = 0;

            let max_depth = self
                .graph
                .edges_directed(n, Direction::Incoming)
                .map(|e| {
                    let id = e.source().id();
                    *pbs_depth.get(&id).unwrap()
                })
                .max()
                .unwrap_or(0);

            let this_depth = match self.graph.node_weight(n).unwrap() {
                FheOp::Pbs => max_depth + 1,
                _ => max_depth,
            };

            pbs_depth.insert(n, this_depth);
        }

        *pbs_depth.values().max().unwrap()
    }
}

pub fn insert_clone(prev: usize, this: usize) {
    append_node(this, |ctx| {
        let prev = *ctx.id_map.get(&prev).unwrap();

        let new = ctx.graph.add_node(FheOp::Clone);
        ctx.graph.add_edge(prev, new, ());

        new
    });
}

pub fn insert_input(this: usize) {
    append_node(this, |ctx| {
        let node = ctx.graph.add_node(FheOp::Input);

        node
    });
}

pub fn insert_add(left: usize, right: usize, this: usize) {
    append_node(this, |ctx| {
        let node = ctx.graph.add_node(FheOp::Add);
        let left = ctx.id_map.get(&left).unwrap();
        let right = ctx.id_map.get(&right).unwrap();

        ctx.graph.add_edge(*left, node, ());
        ctx.graph.add_edge(*right, node, ());

        node
    });
}

pub fn insert_univariate_pbs(prev: usize, this: usize) {
    append_node(this, |ctx| {
        let node = ctx.graph.add_node(FheOp::Pbs);
        let prev = ctx.id_map.get(&prev).unwrap();

        ctx.graph.add_edge(*prev, node, ());

        node
    })
}

pub fn insert_scalar_add(prev: usize, this: usize) {
    append_node(this, |ctx| {
        let node = ctx.graph.add_node(FheOp::ScalarAdd);
        let prev = ctx.id_map.get(&prev).unwrap();

        ctx.graph.add_edge(*prev, node, ());

        node
    });
}

pub fn insert_trivial(this: usize) {
    append_node(this, |ctx| {
        let node = ctx.graph.add_node(FheOp::Trivial);

        node
    });
}

fn append_node<F: Fn(&mut TraceCtx) -> NodeIndex>(id: usize, f: F) {
    match &mut *get_ctx() {
        Some(ctx) => {
            let nid = f(ctx);
            ctx.id_map.insert(id, nid);
        }
        None => {}
    }
}

static CTX: Mutex<Option<TraceCtx>> = Mutex::new(None);

pub fn new_ctx() {
    *CTX.lock().unwrap() = Some(TraceCtx {
        graph: StableGraph::new(),
        id_map: HashMap::new(),
    });
}

fn get_ctx() -> MutexGuard<'static, Option<TraceCtx>> {
    CTX.lock().unwrap()
}

fn dump_ctx(filename: &str) {
    use petgraph::dot::Config as PetgraphConfig;

    match &*get_ctx() {
        Some(x) => {
            let content = format!(
                "{:?}",
                petgraph::dot::Dot::with_config(&x.graph, &[PetgraphConfig::EdgeNoLabel])
            );

            std::fs::write(filename, content).unwrap();
        }
        None => {}
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FheOp {
    Pbs,
    ScalarAdd,
    Sub,
    Add,
    Clone,
    Input,
    Trivial,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generate_keys,
        prelude::{FheEncrypt, FheOrd},
        set_server_key, ConfigBuilder, FheUint8,
    };

    #[test]
    fn add_8() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        new_ctx();
        let val = FheUint8::encrypt(123u8, &client_key);

        set_server_key(server_key);

        let c = &val + &val;

        println!("{}", get_ctx().as_ref().unwrap().pbs_critical_path());

        dump_ctx("add8");
    }

    #[test]
    fn add_16() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        new_ctx();
        let val = FheUint16::encrypt(123u8, &client_key);

        set_server_key(server_key);

        let c = &val + &val;

        println!("{}", get_ctx().as_ref().unwrap().pbs_critical_path());

        dump_ctx("add16");
    }

    #[test]
    fn add_32() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        new_ctx();
        let val = FheUint32::encrypt(123u8, &client_key);

        set_server_key(server_key);

        let c = &val + &val;

        println!("{}", get_ctx().as_ref().unwrap().pbs_critical_path());

        dump_ctx("add32");
    }

    #[test]
    fn mul_8() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        new_ctx();
        let val = FheUint8::encrypt(123u8, &client_key);

        set_server_key(server_key);

        let c = &val * &val;

        println!("{}", get_ctx().as_ref().unwrap().pbs_critical_path());

        dump_ctx("mul8");
    }

    #[test]
    fn mul_16() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        new_ctx();
        let val = FheUint16::encrypt(123u8, &client_key);

        set_server_key(server_key);

        let c = &val * &val;

        println!("{}", get_ctx().as_ref().unwrap().pbs_critical_path());

        dump_ctx("mul16");
    }

    #[test]
    fn mul_32() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        new_ctx();
        let val = FheUint32::encrypt(123u8, &client_key);

        set_server_key(server_key);

        let c = &val * &val;

        println!("{}", get_ctx().as_ref().unwrap().pbs_critical_path());

        dump_ctx("mul32");
    }

    #[test]
    fn cmp_8() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        new_ctx();
        let val = FheUint8::encrypt(123u8, &client_key);

        set_server_key(server_key);

        let c = &val.lt(&val);

        println!("{}", get_ctx().as_ref().unwrap().pbs_critical_path());

        dump_ctx("lt8");
    }

    #[test]
    fn cmp_16() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        new_ctx();
        let val = FheUint16::encrypt(123u8, &client_key);

        set_server_key(server_key);

        let c = &val.lt(&val);

        println!("{}", get_ctx().as_ref().unwrap().pbs_critical_path());

        dump_ctx("lt16");
    }

    #[test]
    fn cmp_32() {
        let config = ConfigBuilder::default().build();
        let (client_key, server_key) = generate_keys(config);

        new_ctx();
        let val = FheUint32::encrypt(123u8, &client_key);

        set_server_key(server_key);

        let c = &val.lt(&val);

        println!("{}", get_ctx().as_ref().unwrap().pbs_critical_path());

        dump_ctx("lt32");
    }
}
