use std::hash::Hash;

use keccak_hash::{H256, keccak};

pub struct MerkleTree {
    root: H256,
    hashes: Vec<Vec<H256>>,
    len: usize,
    levels: usize,
}

impl MerkleTree {
    pub fn new() -> Self {
        MerkleTree {
            root: keccak_hash::H256([0u8; 32]),
            hashes: vec![vec![]],
            len: 0,
            levels: 1,
        }
    }

    pub fn get_root(&self) -> H256 {
        self.root
    }

    pub fn append<T>(&mut self, element: &T)
    where
        T: Hash + std::convert::AsRef<[u8]>,
    {
        let hashed_element = keccak(element);
        self.hashes[0].insert(self.len, hashed_element);
        self.len += 1;
        self.recompute_tree();
    }

    pub fn recompute_tree(&mut self) {
        if self.len == 1 {
            self.root = self.hashes[0][0];
            return;
        }

        if self.len > usize::pow(2 as usize,self.levels as u32){
            self.levels += 1;
        }
        
        let max_index = usize::pow(2 as usize,self.levels as u32);
        for i in self.len..max_index {
            let element = self.hashes[0][self.len - 1].clone();
            self.hashes[0].insert(i, element);
        }

        let aux = self.hashes[0].clone();
        self.hashes = vec![aux];

        for level in 1..self.levels + 1 {
            self.hashes.push(vec![]);
            for i in 0..self.hashes[level - 1].len() / 2 {
                let lc: H256 = self.hashes[level - 1][2 * i];
                let rc: H256 = self.hashes[level - 1][2 * i + 1];
                let concatenated = [lc.as_bytes(), rc.as_bytes()].concat();
                self.hashes[level].push(keccak(concatenated));
            }
        }
        self.root = self.hashes[self.levels][0];
    }
}

impl<T> From<Vec<T>> for MerkleTree
where
    T: Hash + std::convert::AsRef<[u8]>,
{
    fn from(arr: Vec<T>) -> Self {
        let mut mt = MerkleTree::new();

        for element in arr {
            mt.append(&element);
        }

        mt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_leaf() {
        let hashed = keccak("Keccak.com".as_bytes());

        let mut mt = MerkleTree::new();
        mt.append(&"Keccak.com".as_bytes());

        assert_eq!(mt.get_root(), hashed);
    }

    #[test]
    fn two_leaves() {
        let mut mt = MerkleTree::new();
        let a = "keccak.com".as_bytes();
        let b = "example.com".as_bytes();

        mt.append(&a);
        mt.append(&b);

        let concatenated = &[keccak(a).as_bytes(), keccak(b).as_bytes()].concat();

        assert_eq!(mt.get_root(), keccak(concatenated));
    }

    #[test]
    fn three_leaves() {
        // a fourth element should be copied from the last element
        let mut mt = MerkleTree::new();
        let a = "keccak.com".as_bytes();
        let b = "example.com".as_bytes();
        let c = "mechardo3d.xyz".as_bytes();

        mt.append(&a);
        mt.append(&b);
        mt.append(&c);


        let a_b = &[keccak(a).as_bytes(), keccak(b).as_bytes()].concat();
        let c_c = &[keccak(c).as_bytes(), keccak(c).as_bytes()].concat();

        let concatenated = &[keccak(a_b).as_bytes(), keccak(c_c).as_bytes()].concat();


        assert_eq!(mt.get_root(), keccak(concatenated));
    }

}
