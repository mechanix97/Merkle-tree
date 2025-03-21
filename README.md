# Merkle-tree
A Merkle tree implementation with Rust

# Overview
A Merkle tree or Hash tree is a tree data stucture that consist of leaves which are formed from the hashes their chlilds as shown in the image below. Finally, the depest leaves have hashes of the data blocks. The tree is widely used in cryptography as they can prove that a block is in the tree only using log(n) leaves (n is the number of blocks).

![Merkle tree](https://upload.wikimedia.org/wikipedia/commons/9/95/Hash_Tree.svg)
(image extracted from wikipedia)

## Usage
To use it run:
```shell
make 
```
or to test it:
```shell
make test 
```