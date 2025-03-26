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
        self.hashes[0].insert(self.len, hashed_element);
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
        while self.len > usize::pow(2 as usize, self.levels as u32) {
            self.levels += 1;
        }

        // complete the array to fill 2^n elements
        for i in self.len..usize::pow(2 as usize, self.levels as u32) {
            self.hashes[0].insert(i, keccak(""));
        }

        // traverse the tree by levels
        for level in 1..self.levels + 1 {
            // clear the level to recompute the hashes
            if self.hashes.len() <= level {
                self.hashes.insert(level, vec![]);
            }

            // divide the index by 2 each level
            index = index / 2;

            // each level has half the elements of the previous levels
            for i in index..self.hashes[level - 1].len() / 2 {
                let lc: H256 = self.hashes[level - 1][2 * i];
                let rc: H256 = self.hashes[level - 1][2 * i + 1];
                let concatenated = [lc.as_bytes(), rc.as_bytes()].concat();
                self.hashes[level].insert(i, keccak(concatenated));
            }
        }

        // save the root hash for easy access
        self.root = self.hashes[self.levels][0];
    }

    // generate a proof from a given index
    pub fn generate_proof(&self, mut index: usize) -> Vec<H256> {
        if index >= self.len {
            return vec![];
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

        output
    }

    // checks if a proof of a certain element is valid
    // receives the element, the proof (array of hashes) and the position of the element
    pub fn check_proof(&self, element: H256, proof: Vec<H256>, mut index: usize) -> bool {
        if index >= self.len {
            return false;
        }

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
        let c_c = &[keccak(c).as_bytes(), keccak("").as_bytes()].concat();

        let concatenated = &[keccak(a_b).as_bytes(), keccak(c_c).as_bytes()].concat();

        assert_eq!(mt.get_root(), keccak(concatenated));
    }

    #[test]
    fn proof_three_leaves() {
        // a fourth element should be added
        let mt = MerkleTree::from(vec!["keccak.com", "example.com", "mechardo3d.xyz"]);

        let proof = vec![
            keccak(""),
            keccak(
                &[
                    keccak("keccak.com").as_bytes(),
                    keccak("example.com").as_bytes(),
                ]
                .concat(),
            ),
        ];

        assert_eq!(mt.generate_proof(2), proof);
    }

    #[test]
    fn proof_index_too_big() {
        // a fourth element should be added
        let mt = MerkleTree::from(vec!["keccak.com", "example.com", "mechardo3d.xyz"]);

        assert_eq!(mt.generate_proof(3), vec!());
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
        let c_c = &[keccak(c).as_bytes(), keccak("").as_bytes()].concat();

        let concatenated = &[keccak(a_b).as_bytes(), keccak(c_c).as_bytes()].concat();

        assert_eq!(mt.get_root(), keccak(concatenated));
    }

    #[test]
    pub fn very_large_tree() {
        let elems = vec!["google.com"; 254];

        let mut mt = MerkleTree::from(elems);
        mt.append(&"google.com");

        // this root has been verified manually
        let root = [
            202, 102, 178, 60, 100, 108, 0, 66, 35, 35, 124, 87, 13, 238, 233, 107, 132, 211, 45,
            174, 237, 164, 205, 171, 133, 196, 169, 23, 20, 223, 137, 111,
        ];

        assert_eq!(mt.get_root(), H256(root));
    }

    #[test]
    pub fn generate_proof_and_validate() {
        let elems = vec!["google.com"; 254];

        let mt = MerkleTree::from(elems);
        let proof = mt.generate_proof(45);

        assert!(mt.check_proof(keccak("google.com"), proof, 45));
    }
}
