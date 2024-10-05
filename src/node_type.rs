use std::cmp::Ordering;
use std::io::Error;
use crate::page_layout::PTR_SIZE;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Offset(pub usize);

/// 将长度为len(usize)的数组转换为大端整数形式的usize。
impl TryFrom<[u8; PTR_SIZE]> for Offset {
    type Error = Error;
    fn try_from(value: [u8; PTR_SIZE]) -> Result<Self, Self::Error> {
        Ok(Offset(usize::from_be_bytes(value)))
    }
}

#[derive(Clone, Eq, PartialEq, PartialOrd, Ord, Debug)]
pub struct Key(pub String);


// 定义key value的数据对
#[derive(Clone, Eq, Debug)]
pub struct KeyValuePair {
    pub key: String,
    pub value: String,
}

impl Ord for KeyValuePair {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key)
    }
}

impl PartialOrd for KeyValuePair {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for KeyValuePair {
    fn eq(&self, other: &Self) -> bool {
        self.key == other.key && self.value == other.value
    }
}

impl KeyValuePair {
    pub fn new(key: String, value: String) -> Self {
        KeyValuePair { key, value }
    }
}


#[derive(PartialEq, Eq, Clone, Debug)]
pub enum NodeType {
    /// Internal nodes contain a vector of pointers to their children and a vector of keys.
    /// 内部节点
    Internal(Vec<Offset>, Vec<Key>),

    /// Leaf nodes contain a vector of Keys and values.
    /// 叶子节点
    Leaf(Vec<KeyValuePair>),

    Unexpected,
}


// Converts a byte to a NodeType.
impl From<u8> for NodeType {
    fn from(value: u8) -> Self {
        match value {
            0x01 => NodeType::Internal(Vec::<Offset>::new(), Vec::<Key>::new()),
            0x02 => NodeType::Leaf(Vec::<KeyValuePair>::new()),
            _ => NodeType::Unexpected,
        }
    }
}

// Converts a NodeType to a byte.
impl From<NodeType> for u8 {
    fn from(value: NodeType) -> Self {
        match value {
            NodeType::Internal(_, _) => 0x01,
            NodeType::Leaf(_) => 0x02,
            NodeType::Unexpected => 0x00,
        }
    }
}
