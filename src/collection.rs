use collections::Vec;

use system::error::Result;

use super::{ExNode, FileSystem, Node};

/// A collection of a Node and its associated ExNodes
pub struct Collection {
    pub node: (u64, Node),
    pub ex_nodes: Vec<(u64, ExNode)>
}

impl Collection {
    pub fn load(fs: &mut FileSystem, block: u64) -> Result<Collection> {
        let node = try!(fs.node(block));

        let mut next = node.1.next;
        let mut ex_nodes = Vec::new();
        while next > 0 {
            let ex_node = try!(fs.ex_node(next));
            next = ex_node.1.next;
            ex_nodes.push(ex_node);
        }

        Ok(Collection {
            node: node,
            ex_nodes: ex_nodes,
        })
    }
}
