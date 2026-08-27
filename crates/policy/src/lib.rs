use aa_types::ModuleEntity;
use alloy_primitives::Address;
use petgraph::graph::DiGraph;
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AuthorityNode {
    Validation {
        entity: ModuleEntity,
        is_global: bool,
    },
    Selector {
        selector: [u8; 4],
    },
    Target {
        address: Address,
    },
}
#[derive(Debug, Clone, PartialEq)]
pub enum AuthorityEdge {
    ValidatesFor { via_global: bool }, // true = only reachable via isGlobal+allowGlobalValidation
    Invokes,
}
pub struct AuthorityGraph {
    pub graph: DiGraph<AuthorityNode, AuthorityEdge>,
    node_index: HashMap<AuthorityNode, NodeIndex>,
}
#[derive(Debug, Clone)]
pub struct Finding {
    pub entity: ModuleEntity,
    pub selector: [u8; 4],
    pub target: Address,
    pub reason: String,
}

impl AuthorityGraph {
    pub fn new() -> Self {
        Self {
            graph: DiGraph::new(),
            node_index: HashMap::new(),
        }
    }
    fn get_or_insert(&mut self, node: AuthorityNode) -> NodeIndex {
        if let Some(&idx) = self.node_index.get(&node) {
            return idx;
        }
        let idx = self.graph.add_node(node.clone());
        self.node_index.insert(node, idx);
        idx
    }
    /// Records that a validation entity may authorize a given selector.
    pub fn add_validates_for(
        &mut self,
        entity: ModuleEntity,
        is_global: bool,
        selector: [u8; 4],
        explicitly_scoped: bool,
    ) {
        let validator_node = self.get_or_insert(AuthorityNode::Validation { entity, is_global });
        let selector_node = self.get_or_insert(AuthorityNode::Selector { selector });
        let via_global = is_global && !explicitly_scoped;
        self.graph.add_edge(
            validator_node,
            selector_node,
            AuthorityEdge::ValidatesFor { via_global },
        );
    }

    /// Records that a selector, when executed, invokes a given contract.
    pub fn add_invokes(&mut self, selector: [u8; 4], target: Address) {
        let selector_node = self.get_or_insert(AuthorityNode::Selector { selector });
        let target_node = self.get_or_insert(AuthorityNode::Target { address: target });
        self.graph
            .add_edge(selector_node, target_node, AuthorityEdge::Invokes);
    }
    pub fn find_privilege_amplification(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        for edge_ref in self.graph.edge_references() {
            if let AuthorityEdge::ValidatesFor { via_global: true } = edge_ref.weight() {
                let val_node = &self.graph[edge_ref.source()];
                let sel_node = &self.graph[edge_ref.target()];

                if let (
                    AuthorityNode::Validation { entity, .. },
                    AuthorityNode::Selector { selector },
                ) = (val_node, sel_node)
                {
                    // Walk forward from the selector to whatever target it invokes.
                    for target_edge in self.graph.edges(edge_ref.target()) {
                        if let AuthorityNode::Target { address } = &self.graph[target_edge.target()]
                        {
                            findings.push(Finding {
                                entity: entity.clone(),
                                selector: *selector,
                                target: *address,
                                reason: "reaches selector via global validation escape hatch, not explicit scoping".into(),
                            });
                        }
                    }
                }
            }
        }

        findings
    }

    pub fn find_validation_applicability_violations(&self) -> Vec<Finding> {
        let mut findings = Vec::new();

        let invoked_selectors: Vec<(NodeIndex, [u8; 4])> = self
            .graph
            .node_indices()
            .filter_map(|idx| {
                if let AuthorityNode::Selector { selector } = &self.graph[idx] {
                    Some((idx, *selector))
                } else {
                    None
                }
            })
            .collect();

        // Step 2: for every Validation node in the graph.....

        for val_idx in self.graph.node_indices() {
            let AuthorityNode::Validation { entity, .. } = &self.graph[val_idx] else {
                continue;
            };

            // Step 3: .... check each invloed Selector: does an edge exist
            // from this validator to this selecotr at all ?
            for &(sel_idx, selector) in &invoked_selectors {
                let has_edge = self.graph.find_edge(val_idx, sel_idx).is_some();

                if !has_edge {
                    findings.push(Finding {
                        entity: entity.clone(),
                        selector,
                        target: Address::ZERO, // no valid path, so no specific target
                        reason: "validator has no authorization path to this selector at all"
                            .into(),
                    });
                }
            }
        }
        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_key_entity() -> ModuleEntity {
        ModuleEntity {
            module: Address::repeat_byte(0x01),
            entity_id: 1,
        }
    }

    #[test]
    fn creates_empty_graph() {
        let g = AuthorityGraph::new();
        assert_eq!(g.graph.node_count(), 0);
    }
    #[test]
    fn builds_safe_path() {
        let mut g = AuthorityGraph::new();
        let transfer_selector = [0x11, 0x22, 0x33, 0x44];
        let usdc = Address::repeat_byte(0xAA);

        g.add_validates_for(session_key_entity(), false, transfer_selector, true);
        g.add_invokes(transfer_selector, usdc);

        assert_eq!(g.graph.node_count(), 3); // validation, selector, target
        assert_eq!(g.graph.edge_count(), 2);
    }
    #[test]
    fn does_not_duplicate_shared_selector_node() {
        let mut g = AuthorityGraph::new();
        let selector = [0x99, 0x99, 0x99, 0x99];

        g.add_validates_for(session_key_entity(), false, selector, true);
        g.add_invokes(selector, Address::repeat_byte(0xBB));

        // selector node should be shared/reused, not duplicated
        let selector_nodes = g
            .graph
            .node_weights()
            .filter(|n| matches!(n, AuthorityNode::Selector { selector: s } if *s == selector))
            .count();
        assert_eq!(selector_nodes, 1);
    }
}
