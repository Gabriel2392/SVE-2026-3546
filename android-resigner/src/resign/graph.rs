use std::collections::{BTreeMap, BTreeSet, VecDeque};

use anyhow::{bail, Context, Result};

#[derive(Clone, Debug)]
pub(super) struct DependencyGraph {
    nodes: BTreeSet<String>,
    requires: BTreeMap<String, BTreeSet<String>>,
    consumers: BTreeMap<String, BTreeSet<String>>,
}

impl DependencyGraph {
    pub(super) fn new(
        nodes: impl IntoIterator<Item = String>,
        requires: &BTreeMap<String, Vec<String>>,
    ) -> Result<Self> {
        let nodes = nodes.into_iter().collect::<BTreeSet<_>>();
        if nodes.is_empty() { bail!("image dependency list is empty") }
        let mut normalized = BTreeMap::new();
        let mut consumers = BTreeMap::<String, BTreeSet<String>>::new();
        for (target, inputs) in requires {
            if !nodes.contains(target) { bail!("required output {target:?} is not a configured image") }
            let raw_count = inputs.len();
            let inputs = inputs.iter().cloned().collect::<BTreeSet<_>>();
            if inputs.len() != raw_count { bail!("dependency list for {target:?} contains duplicates") }
            if inputs.contains(target) { bail!("image {target:?} depends on itself") }
            for input in &inputs {
                if !nodes.contains(input) { bail!("dependency input {input:?} for {target:?} is not configured") }
                consumers.entry(input.clone()).or_default().insert(target.clone());
            }
            normalized.insert(target.clone(), inputs);
        }
        let graph = Self { nodes, requires: normalized, consumers };
        graph.topological(&graph.nodes)?;
        Ok(graph)
    }

    pub(super) fn affected(&self, changed: &BTreeSet<String>) -> Result<BTreeSet<String>> {
        for name in changed {
            if !self.nodes.contains(name) { bail!("changed image {name:?} is not configured") }
        }
        let mut affected = changed.clone();
        let mut queue = changed.iter().cloned().collect::<VecDeque<_>>();
        while let Some(name) = queue.pop_front() {
            for consumer in self.consumers.get(&name).into_iter().flatten() {
                if affected.insert(consumer.clone()) { queue.push_back(consumer.clone()); }
            }
        }
        Ok(affected)
    }

    pub(super) fn rebuild_order(&self, changed: &BTreeSet<String>) -> Result<Vec<String>> {
        let affected = self.affected(changed)?;
        self.topological(&affected)
    }

    fn topological(&self, selected: &BTreeSet<String>) -> Result<Vec<String>> {
        let mut pending = selected.iter().map(|name| {
            let count = self.requires.get(name).into_iter().flatten().filter(|item| selected.contains(*item)).count();
            (name.clone(), count)
        }).collect::<BTreeMap<_, _>>();
        let mut ready = pending.iter().filter_map(|(name, &count)| (count == 0).then_some(name.clone())).collect::<BTreeSet<_>>();
        let mut order = Vec::with_capacity(selected.len());
        while let Some(name) = ready.pop_first() {
            if pending.remove(&name).is_none() { continue }
            order.push(name.clone());
            for consumer in self.consumers.get(&name).into_iter().flatten().filter(|item| selected.contains(*item)) {
                let count = pending.get_mut(consumer).context("selected dependency consumer is missing")?;
                *count -= 1;
                if *count == 0 { ready.insert(consumer.clone()); }
            }
        }
        if !pending.is_empty() { bail!("image dependencies contain a cycle involving {:?}", pending.keys().collect::<Vec<_>>()) }
        Ok(order)
    }
}
