#![allow(dead_code)]
#![allow(unused)]

pub mod route {

    use crate::{RipError, MacAddress};
    use std::sync::{Arc, RwLock, Mutex};
    use std::net::Ipv4Addr;
    use radix_trie::{Trie, TrieKey};

    /// A routing rule in the routing table. 
    /// Rules are applied in the Longest-Prefix-Match fashion.
    /// Multiple choices are supported, as a RoutingRule can specify a set
    /// of next-hop IPs. 
    pub struct RoutingRule {
        pub key: RoutingRuleKey,
        pub value: RoutingRuleValue,
    }

    #[derive(Eq, PartialEq, Clone, Copy, Debug)]
    pub struct RoutingRuleKey {
        /// Destination IP
        pub dst_ip: u32,
        /// Prefix length, or equivalently the IP mask
        pub prefix_length: u8,
    }
    impl RoutingRuleKey {
        pub fn new(dst_ip: Ipv4Addr, prefix_length: u8) -> Self {
            let mask = !(((1u64<<(32-prefix_length))-1) as u32);
            let ip = u32::from_be_bytes(dst_ip.octets());
            
            RoutingRuleKey {
                dst_ip: ip & mask,
                prefix_length,
            }
        }

        pub fn from_exact(dst_ip: Ipv4Addr) -> Self {
            RoutingRuleKey {
                dst_ip: u32::from_be_bytes(dst_ip.octets()),
                prefix_length: 32
            }
        }
    }

    /// Due to implementation complexity, the `recvIP` in a RoutingRuleValue
    /// might be substituted with `recvMacAddr`. This utility enum helps unify
    /// the handling of this problem.
    #[derive(Debug, Copy, Clone)]
    pub enum IPorMAC {
        IPv4(Ipv4Addr),
        Mac(MacAddress),
    }

    #[derive(Debug)]
    pub struct RoutingRuleValue {
        /// Next-hop choices. The tuple is (nextHopIP, recv)
        pub choices: Vec<(Ipv4Addr, IPorMAC)>,
    }

    impl TrieKey for RoutingRuleKey {
        fn encode_bytes(&self) -> Vec<u8> {
            // To implement strict LPM, the encoding is a bit inefficient.
            (32-self.prefix_length as usize..32)
                .rev()
                .map(|idx| ((self.dst_ip & (1<<idx)) != 0) as u8)
                .collect()
        }
    }

    /// A routing table that is double-buffered. 
    /// Accesses and substitution to the actual routing table are Rwlocked,
    /// while modifications to the shadow table requires no locking. Once
    /// the shadow table is ready, the writer lock is grabbed to swap out 
    /// the actual table.
    /// The table it self is a Trie tree.
    pub struct RoutingTable {
        // Actual routing table. Multi-threaded, with Rwlock.
        table: Arc<RwLock<Option<Trie<RoutingRuleKey, RoutingRuleValue>>>>,
        // The shadow table, for modification
        shadow_table: Option<Trie<RoutingRuleKey, RoutingRuleValue>>,
        // Set of manually configurated rules
        rules: Arc<Mutex<Vec<RoutingRule>>>,
    }

    impl RoutingTable {

        /// Initiate the routing table
        pub fn init() -> RoutingTable {
            RoutingTable {
                table: Arc::new(RwLock::new(Some(Trie::new()))),
                shadow_table: Some(Trie::new()),
                rules: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// Clone a new reference to the routing table for reading
        pub fn get_table_reader(&self) -> Arc<RwLock<Option<Trie<RoutingRuleKey, RoutingRuleValue>>>> {
            self.table.clone()
        }

        /// Clone a new reference to the rules for modification
        pub fn get_rules_writer(&self) -> Arc<Mutex<Vec<RoutingRule>>> {
            self.rules.clone()
        }

        /// Query the routing table
        pub fn route(
            handle: &Arc<RwLock<Option<Trie<RoutingRuleKey, RoutingRuleValue>>>>,
            ip: Ipv4Addr,
            callback: Option<Box<dyn Fn(&Vec<(Ipv4Addr,IPorMAC)>)->Option<(Ipv4Addr,IPorMAC)>>>,
        ) -> Option<(Ipv4Addr, IPorMAC)> 
        {
            let guard = handle.read().unwrap();
            let table = guard.as_ref().unwrap();
            let key = RoutingRuleKey::from_exact(ip);

            match table.get_ancestor_value(&key) {
                Some(rule) => {
                    if let Some(callback) = callback {
                        callback(&rule.choices)
                    }
                    else {
                        // Default is to take the first choice
                        if rule.choices.is_empty() {
                            None
                        }
                        else {
                            Some(rule.choices[0])
                        }
                    }
                }
                None => {
                    println!("should not happen");
                    None
                },
            }
        }

        /// Add a new routing rule to the shadow table. Note that newer value of a key
        /// overwrites the old value. To add multiple choices to an entry, the caller
        /// should provide them in `choices` as argument.
        pub fn add_to_shadow_table(
            &mut self,
            ip: Ipv4Addr,
            choices: Vec<(Ipv4Addr, IPorMAC)>) 
        {
            let mut shadow_table = self.shadow_table.as_mut().unwrap();
            shadow_table.insert(
                RoutingRuleKey::from_exact(ip), 
                RoutingRuleValue { choices },
            );
        }

        /// Flip the shadow table as the actual table. First append the manually set
        /// `rules`, then replace and discard the old table. Finally prepare a new clean
        /// shadow table.
        pub fn flip(&mut self) {
            // Append user specified rules
            let guard = self.rules.lock().unwrap();
            let mut shadow_table = self.shadow_table.take().unwrap();
            for rule in guard.iter() {
                shadow_table.insert(rule.key, RoutingRuleValue{
                    choices: rule.value.choices.clone(),
                });
            }
            drop(guard);

            // Flip the routing table
            let mut guard = self.table.write().unwrap();
            guard.replace(shadow_table);
            // Shadow table now flipped, the old table dropped implictly
            drop(guard);

            // Prepare new shadow table
            let mut shadow_table = Trie::new();
            self.shadow_table.insert(shadow_table);
        }
    }
}