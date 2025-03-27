use keccak_hash::{H256, keccak};
use std::hash::Hash;

pub struct MerkleTree {
    root: H256,
    hashes: Vec<Vec<H256>>,
    len: usize,
    levels: usize,
}

impl MerkleTree {
    fn new() -> Self {
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
        if self.len < self.hashes[0].len() {
            self.hashes[0][self.len] = hashed_element;
        } else {
            self.hashes[0].insert(self.len, hashed_element);
        }

        self.len += 1;
        self.recompute_tree_from_index(self.len - 1);
    }

    fn recompute_tree(&mut self) {
        self.recompute_tree_from_index(0);
    }

    fn recompute_tree_from_index(&mut self, mut index: usize) {
        if self.len == 1 {
            self.root = self.hashes[0][0];
            return;
        }

        // check if new levels are needed
        while self.len > 2 && self.len >= (1 << self.levels)+ 1 {
            self.levels += 1;
        }

        // complete the array to fill 2^n elements
        for i in self.hashes[0].len()..(1 << self.levels) {
            self.hashes[0].insert(i, keccak([0u8; 32]));
        }

        // traverse the tree by levels
        for level in 1..self.levels + 1 {
            // insert new level if needed
            if self.hashes.len() <= level {
                self.hashes.insert(level, vec![]);
            }

            // divide the index by 2 each level
            index >>= 1;

            // each level has half the elements of the previous levels
            let limit = (self.hashes[level - 1].len() + 1) / 2;

            for i in index..limit {
                let lc: H256 = self.hashes[level - 1][2 * i];
                let rc: H256 = self.hashes[level - 1][2 * i + 1];
                let concatenated = [lc.as_bytes(), rc.as_bytes()].concat();
                if i >= self.hashes[level].len() {
                    self.hashes[level].push(keccak(concatenated));
                } else {
                    self.hashes[level][i] = keccak(concatenated);
                }
            }
        }

        // save the root hash for easy access
        self.root = self.hashes[self.levels][0];
    }

    // generate a proof from a given index
    pub fn generate_proof(&self, mut index: usize) -> Option<Vec<H256>> {
        if index >= self.len {
            return None;
        }

        let mut output = vec![];
        for i in 0..self.levels {
            if index % 2 == 0 {
                output.push(self.hashes[i][index + 1]);
            } else {
                output.push(self.hashes[i][index - 1]);
            }
            index = index / 2;
        }

        Some(output)
    }

    // checks if a proof of a certain element is valid
    // receives the element, the proof (array of hashes) and the position of the element
    pub fn check_proof(&self, element: H256, proof: Vec<H256>, mut index: usize) -> bool {
        if index >= self.len {
            return false;
        }
        self.print();
        let mut hash: H256 = element;

        for elem in proof {
            if index % 2 == 0 {
                let concatenated = [hash.as_bytes(), elem.as_bytes()].concat();
                hash = keccak(concatenated);
            } else {
                let concatenated = [elem.as_bytes(), hash.as_bytes()].concat();
                hash = keccak(concatenated);
            }
            index = index / 2;
        }

        hash == self.root
    }

    pub fn print(&self) {
        for i in 0..self.hashes.len() {
            for j in 0..self.hashes[i].len() {
                print!("[{i}][{j}] {:x}", self.hashes[i][j]);
            }
            println!("");
        }
    }
}

impl<T> From<Vec<T>> for MerkleTree
where
    T: Hash + std::convert::AsRef<[u8]>,
{
    fn from(arr: Vec<T>) -> Self {
        let mut mt = MerkleTree::new();

        for element in arr {
            mt.hashes[0].push(keccak(element));
            mt.len += 1;
        }
        //recompute the tree from the start
        mt.recompute_tree();

        mt
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_leaf() {
        let hashed = keccak("Keccak.com");

        let mt = MerkleTree::from(vec!["Keccak.com"]);

        assert_eq!(mt.get_root(), hashed);
    }

    #[test]
    fn two_leaves() {
        let a = "keccak.com";
        let b = "example.com";
        let mt = MerkleTree::from(vec![a, b]);

        let concatenated = &[keccak(a).as_bytes(), keccak(b).as_bytes()].concat();

        assert_eq!(mt.get_root(), keccak(concatenated));
    }

    #[test]
    fn three_leaves() {
        let a = "keccak.com";
        let b = "example.com";
        let c = "mechardo3d.xyz";

        // a fourth element should be added
        let mt = MerkleTree::from(vec!["keccak.com", "example.com", "mechardo3d.xyz"]);

        let a_b = &[keccak(a).as_bytes(), keccak(b).as_bytes()].concat();
        let c_c = &[keccak(c).as_bytes(), keccak([0u8; 32]).as_bytes()].concat();

        let concatenated = &[keccak(a_b).as_bytes(), keccak(c_c).as_bytes()].concat();

        assert_eq!(mt.get_root(), keccak(concatenated));
    }

    #[test]
    fn proof_three_leaves() {
        // a fourth element should be added
        let mt = MerkleTree::from(vec!["keccak.com", "example.com", "mechardo3d.xyz"]);

        let proof = vec![
            keccak([0u8; 32]),
            keccak(
                &[
                    keccak("keccak.com").as_bytes(),
                    keccak("example.com").as_bytes(),
                ]
                .concat(),
            ),
        ];

        assert_eq!(mt.generate_proof(2).unwrap(), proof);
    }

    #[test]
    fn proof_index_too_big() {
        // a fourth element should be added
        let mt = MerkleTree::from(vec!["keccak.com", "example.com", "mechardo3d.xyz"]);

        assert_eq!(mt.generate_proof(3), None);
    }

    #[test]
    fn check_proof() {
        let mt = MerkleTree::from(vec![
            "keccak.com",
            "example.com",
            "mechardo3d.xyz",
            "google.com",
        ]);

        let proof = vec![
            keccak("google.com"),
            keccak(
                &[
                    keccak("keccak.com").as_bytes(),
                    keccak("example.com").as_bytes(),
                ]
                .concat(),
            ),
        ];

        assert!(mt.check_proof(keccak("mechardo3d.xyz"), proof, 2));
    }

    #[test]
    fn append_and_recompute_from() {
        let a = "keccak.com";
        let b = "example.com";
        let c = "mechardo3d.xyz";

        // a fourth element should be added
        let mut mt = MerkleTree::new();
        mt.append(&a);
        mt.append(&b);
        mt.append(&c);

        let a_b = &[keccak(a).as_bytes(), keccak(b).as_bytes()].concat();
        let c_c = &[keccak(c).as_bytes(), keccak([0u8; 32]).as_bytes()].concat();

        let concatenated = &[keccak(a_b).as_bytes(), keccak(c_c).as_bytes()].concat();

        assert_eq!(mt.get_root(), keccak(concatenated));
    }

    #[test]
    pub fn very_large_tree() {
        let elems = vec!["google.com"; 254];

        let mut mt = MerkleTree::from(elems);
        mt.append(&"google.com");

        // this root has been verified manually
        let root: H256 = H256([
            0x3a, 0xfa, 0xf3, 0x8b, 0x49, 0x1f, 0x01, 0x8a, 0x52, 0x03, 0xb3, 0xf4, 0x1a, 0xff,
            0x7c, 0x33, 0xf6, 0x5f, 0x63, 0xff, 0xbf, 0x4c, 0x92, 0xe0, 0x3e, 0xd7, 0x2c, 0x5b,
            0xec, 0x02, 0x53, 0x7f,
        ]);

        assert_eq!(mt.get_root(), root);
    }

    #[test]
    pub fn generate_proof_and_validate() {
        let elems = vec!["google.com"; 254];

        let mt = MerkleTree::from(elems);
        let proof = mt.generate_proof(45).unwrap();

        assert!(mt.check_proof(keccak("google.com"), proof, 45));
    }
}
