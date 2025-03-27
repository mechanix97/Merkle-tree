# Merkle-tree
A Merkle tree implementation with Rust

# Overview
A Merkle tree or Hash tree is a tree data stucture that consist of leaves which are formed from the hashes their chlilds as shown in the image below. Finally, the depest leaves have hashes of the data blocks. The tree is widely used in cryptography as they can prove that a block is in the tree only using log(n) leaves (n is the number of blocks).

![Merkle tree](https://upload.wikimedia.org/wikipedia/commons/9/95/Hash_Tree.svg)
(image extracted from wikipedia)



# Rules
- A Merkle Tree can be built out of an array.
- A Merkle Tree can generate a proof that it contains an element.
- A Merkle Tree can verify that a given hash is contained in it.
- A Merkle Tree can be dynamic, this means that elements can be added once it is built.

## Usage
To use it run:
```shell
make 
```
or to test it:
```shell
make test 
```
## Implementation details

Used a nested array to store the hashes in a bottom-top representation. The first level (hashes[0]) stores an array the hashes of the input elements, and as the array goes down it reatches the root.

Decided to store the len of the first array (hashes[0]) and the count of the levels of the array to have and easy access in the code.

Also stored the root in a separate element in the Merkle tree struct.

Did an optimization when appending a new element into the tree, by only recomputing the leaves that are needed.
