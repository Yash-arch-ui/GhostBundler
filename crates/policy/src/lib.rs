use aa_types::ModuleEntity;
use alloy_primitives::Address;
use petgraph::graph::DiGraph;
use std::collections::HashMap;
use petgraph::graph::NodeIndex;

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
    ValidatesFor,
    Invokes,
}
pub struct AuthorityGraph {
    pub graph: DiGraph<AuthorityNode, AuthorityEdge>,
    node_index: HashMap<AuthorityNode, NodeIndex>,
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_empty_graph() {
        let g = AuthorityGraph::new();
        assert_eq!(g.graph.node_count(), 0);
    }
}
