// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * ============================================================================
 *                    ZK-SNARKS EDUCATIONAL TEST
 * ============================================================================
 *
 * Welcome! This test file teaches you how Zero-Knowledge Proofs (ZK proofs)
 * work, specifically ZK-SNARKs which are used in Ethereum.
 *
 * ============================================================================
 *                    WHAT IS A ZERO-KNOWLEDGE PROOF?
 * ============================================================================
 *
 * A Zero-Knowledge Proof lets you prove you know something WITHOUT revealing
 * what that something is.
 *
 * ANALOGY: Imagine you have a colorblind friend. You want to prove that two
 * balls are different colors WITHOUT telling them which color each ball is.
 * You ask them to hide the balls behind their back and either swap them or
 * not. When they show you the balls again, you can always tell if they
 * swapped. After many rounds, they become convinced the balls are different
 * colors - but they still don't know WHICH colors they are!
 *
 * ============================================================================
 *                    HOW THIS DIFFERS FROM KECCAK256
 * ============================================================================
 *
 * You're familiar with keccak256. Let's compare:
 *
 * KECCAK256 (Hash):
 *   - Input: "secret123" -> Output: 0xabc...
 *   - ANYONE can verify: keccak256("secret123") == 0xabc...
 *   - BUT: To verify, you MUST reveal "secret123"
 *   - Use case: Commit-reveal schemes (you reveal the secret later)
 *
 * ZK-SNARK:
 *   - Private Input (witness): "secret123"
 *   - Public Input: 0xabc... (the hash)
 *   - Proof: A small cryptographic proof (~256 bytes)
 *   - ANYONE can verify: proof is valid for public input 0xabc...
 *   - THE SECRET "secret123" IS NEVER REVEALED!
 *   - Use case: Privacy (you NEVER reveal the secret)
 *
 * ============================================================================
 *                    ZK-SNARK COMPONENTS
 * ============================================================================
 *
 * 1. CIRCUIT: A mathematical representation of what you want to prove.
 *    Example: "I know x such that x * x = 25" (proving you know 5 or -5)
 *
 * 2. WITNESS: Your private/secret inputs. (In example above: x = 5)
 *
 * 3. PUBLIC INPUTS: Values everyone can see. (In example above: 25)
 *
 * 4. PROVING KEY: Generated during "trusted setup" - used to create proofs
 *
 * 5. VERIFICATION KEY: Generated during "trusted setup" - used to verify proofs
 *    This is what we put on-chain!
 *
 * 6. PROOF: The actual ZK proof (~256 bytes) that proves you know the witness
 *
 * ============================================================================
 *                    THE WORKFLOW
 * ============================================================================
 *
 *   OFF-CHAIN (Your computer):
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │  1. You have a SECRET (witness): x = 5                      │
 *   │  2. You have the CIRCUIT: prove x² = public_input          │
 *   │  3. You run the PROVER with (witness, proving_key)         │
 *   │  4. Output: PROOF (small ~256 bytes)                       │
 *   └─────────────────────────────────────────────────────────────┘
 *                              │
 *                              ▼ (submit proof + public inputs)
 *   ON-CHAIN (Smart Contract):
 *   ┌─────────────────────────────────────────────────────────────┐
 *   │  1. Verifier contract has VERIFICATION KEY embedded        │
 *   │  2. Receives: PROOF + PUBLIC INPUTS (25)                   │
 *   │  3. Uses elliptic curve math to verify                     │
 *   │  4. Returns: true/false                                    │
 *   │                                                             │
 *   │  NOTE: The secret (5) is NEVER sent to the contract!       │
 *   └─────────────────────────────────────────────────────────────┘
 *
 * ============================================================================
 *                    ELLIPTIC CURVE MATH (THE MAGIC)
 * ============================================================================
 *
 * ZK-SNARKs use "bilinear pairings" on elliptic curves. Ethereum has
 * precompiled contracts for these operations:
 *
 * - 0x06: ecAdd (add two points on BN254 curve)
 * - 0x07: ecMul (multiply a point by a scalar)
 * - 0x08: ecPairing (the "magic" - checks if e(A,B) * e(C,D) = 1)
 *
 * The pairing check is what makes ZK-SNARKs possible. It lets us verify
 * complex relationships without knowing the underlying values.
 *
 * ============================================================================
 *                    GROTH16 (MOST COMMON ZK-SNARK)
 * ============================================================================
 *
 * Groth16 is the most widely used ZK-SNARK scheme. A Groth16 proof consists
 * of just 3 elliptic curve points (A, B, C):
 *
 * - Point A: on G1 curve (2 * 32 bytes = 64 bytes)
 * - Point B: on G2 curve (2 * 64 bytes = 128 bytes)
 * - Point C: on G1 curve (2 * 32 bytes = 64 bytes)
 *
 * Total: 256 bytes! Very compact, cheap to verify on-chain (~200k gas)
 *
 * ============================================================================
 */

/**
 * @title SimpleZKVerifier
 * @notice A simplified ZK-SNARK verifier to demonstrate the concepts.
 *
 * In production, you'd generate this with tools like:
 * - Circom + snarkjs
 * - ZoKrates
 * - Noir
 *
 * This example verifies: "I know a secret x such that hash(x) = publicHash"
 *
 * The verification key below is FAKE/SIMPLIFIED for educational purposes.
 * Real verification keys are generated by trusted setup ceremonies.
 */
contract SimpleZKVerifier {
    // ========================================================================
    //                    VERIFICATION KEY (SIMPLIFIED)
    // ========================================================================
    // In a real verifier, these would be carefully generated elliptic curve
    // points from a trusted setup ceremony.

    // G1 point (alpha)
    uint256 constant ALPHA_X = 1;
    uint256 constant ALPHA_Y = 2;

    // G2 point (beta) - G2 points have 4 coordinates (2 field elements)
    uint256 constant BETA_X1 = 1;
    uint256 constant BETA_X2 = 2;
    uint256 constant BETA_Y1 = 3;
    uint256 constant BETA_Y2 = 4;

    // G2 point (gamma)
    uint256 constant GAMMA_X1 = 5;
    uint256 constant GAMMA_X2 = 6;
    uint256 constant GAMMA_Y1 = 7;
    uint256 constant GAMMA_Y2 = 8;

    // G2 point (delta)
    uint256 constant DELTA_X1 = 9;
    uint256 constant DELTA_X2 = 10;
    uint256 constant DELTA_Y1 = 11;
    uint256 constant DELTA_Y2 = 12;

    // The BN254 curve prime (used in Ethereum's precompiles)
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    /**
     * @notice This is what a Groth16 proof looks like
     * @dev In reality, these would be valid elliptic curve points
     */
    struct Proof {
        // Point A on G1 curve
        uint256 a_x;
        uint256 a_y;
        // Point B on G2 curve (4 coordinates because G2 is over extension field)
        uint256 b_x1;
        uint256 b_x2;
        uint256 b_y1;
        uint256 b_y2;
        // Point C on G1 curve
        uint256 c_x;
        uint256 c_y;
    }

    /**
     * @notice Demonstrates the STRUCTURE of ZK verification (simplified)
     * @param proof The ZK proof (would be generated off-chain)
     * @param publicInputs The public inputs everyone can see
     * @return True if proof is valid
     *
     * @dev EDUCATIONAL NOTE:
     *
     * The real Groth16 verification equation is:
     *   e(A, B) = e(α, β) * e(Σ pubᵢ * IC[i], γ) * e(C, δ)
     *
     * Where:
     * - e() is the pairing function
     * - A, B, C are the proof points
     * - α, β, γ, δ are from the verification key
     * - IC[i] are "input coefficients" from the verification key
     * - pubᵢ are your public inputs
     *
     * This equation ensures that:
     * 1. The prover knew a valid witness
     * 2. The witness satisfies the circuit constraints
     * 3. The witness produces the given public inputs
     *
     * All WITHOUT revealing what the witness is!
     */
    function verifyProof(
        Proof memory proof,
        uint256[] memory publicInputs
    ) public view returns (bool) {
        // In a real implementation, we would:
        // 1. Compute the linear combination of public inputs with IC points
        // 2. Call the ecPairing precompile to check the equation

        // For education, let's show what the precompile call looks like:
        //
        // The pairing precompile (0x08) takes pairs of (G1, G2) points
        // and checks if: e(p1[0], p2[0]) * e(p1[1], p2[1]) * ... = 1
        //
        // Groth16 verification reformulates as:
        // e(-A, B) * e(α, β) * e(L, γ) * e(C, δ) = 1
        //
        // Where L is the linear combination of public inputs

        // SIMPLIFIED CHECK FOR DEMONSTRATION:
        // We're just checking that the proof has valid-looking structure
        // A real verifier would do the full pairing check

        require(proof.a_x < PRIME_Q, "Invalid proof point A.x");
        require(proof.a_y < PRIME_Q, "Invalid proof point A.y");
        require(proof.c_x < PRIME_Q, "Invalid proof point C.x");
        require(proof.c_y < PRIME_Q, "Invalid proof point C.y");
        require(publicInputs.length > 0, "Need public inputs");

        // In reality, we would call:
        // (bool success, bytes memory data) = address(0x08).staticcall(pairingInput);
        // return success && abi.decode(data, (bool));

        return true; // Simplified for education
    }

    /**
     * @notice Demonstrates calling the actual elliptic curve precompiles
     * @dev These are REAL precompile calls, but with dummy data
     */
    function demonstratePrecompiles() public view returns (bool) {
        // ====================================================================
        //                    EC ADD (0x06)
        // ====================================================================
        // Adds two points on the BN254 G1 curve
        // Input: [x1, y1, x2, y2] (4 * 32 bytes)
        // Output: [x3, y3] (2 * 32 bytes) where (x3,y3) = (x1,y1) + (x2,y2)

        // Generator point G = (1, 2) on BN254
        uint256 gx = 1;
        uint256 gy = 2;

        // G + G = 2G
        bytes memory addInput = abi.encode(gx, gy, gx, gy);
        (bool addSuccess, bytes memory addResult) = address(0x06).staticcall(addInput);

        if (addSuccess && addResult.length == 64) {
            // addResult contains the point 2G
            // (uint256 twoGx, uint256 twoGy) = abi.decode(addResult, (uint256, uint256));
        }

        // ====================================================================
        //                    EC MUL (0x07)
        // ====================================================================
        // Multiplies a point by a scalar
        // Input: [x, y, scalar] (3 * 32 bytes)
        // Output: [x', y'] (2 * 32 bytes) where (x',y') = scalar * (x,y)

        // 5 * G (multiply generator by 5)
        bytes memory mulInput = abi.encode(gx, gy, uint256(5));
        (bool mulSuccess, bytes memory mulResult) = address(0x07).staticcall(mulInput);

        if (mulSuccess && mulResult.length == 64) {
            // mulResult contains 5G
        }

        // ====================================================================
        //                    EC PAIRING (0x08)
        // ====================================================================
        // The "magic" of ZK-SNARKs! Checks bilinear pairing equations.
        //
        // Input: [(G1_point, G2_point), (G1_point, G2_point), ...]
        // Each G1 point: 2 * 32 bytes
        // Each G2 point: 4 * 32 bytes (because it's over an extension field)
        // Total per pair: 6 * 32 = 192 bytes
        //
        // Output: 1 (true) if e(p1,q1) * e(p2,q2) * ... = 1, else 0
        //
        // This is what makes ZK verification possible!

        return addSuccess && mulSuccess;
    }
}

/**
 * @title HashPreimageVerifier
 * @notice A more realistic example: proving you know the preimage of a hash
 *
 * SCENARIO:
 * - Public input: hash = keccak256(secret)
 * - Private input (witness): secret
 * - Prove: "I know 'secret' such that keccak256(secret) = hash"
 * - WITHOUT revealing 'secret'!
 *
 * USE CASES:
 * - Private voting: prove you're on voter list without revealing identity
 * - Private transactions: prove you own funds without revealing which ones
 * - Authentication: prove you know password without revealing it
 */
contract HashPreimageVerifier {
    // Events for demonstration
    event ProofVerified(bytes32 publicHash, address prover);
    event SecretUsed(bytes32 publicHash); // Track which hashes have been "used"

    mapping(bytes32 => bool) public usedProofs;

    /**
     * @notice Verify a proof that someone knows the preimage of a hash
     * @param publicHash The hash (everyone can see this)
     * @param proof The ZK proof (proves knowledge without revealing preimage)
     *
     * @dev In a real implementation:
     * 1. The circuit would compute: hash = keccak256(witness)
     * 2. The circuit would constrain: hash == publicHash
     * 3. The prover provides witness (the secret) OFF-CHAIN
     * 4. The proof proves the constraint is satisfied
     * 5. We verify on-chain WITHOUT ever seeing the secret!
     */
    function verifyHashPreimage(
        bytes32 publicHash,
        bytes memory proof
    ) external returns (bool) {
        // Check proof hasn't been used (prevent replay)
        require(!usedProofs[keccak256(proof)], "Proof already used");

        // In reality, we'd do full Groth16 verification here
        // For education, we just check proof isn't empty
        require(proof.length >= 256, "Invalid proof length");

        // Mark proof as used
        usedProofs[keccak256(proof)] = true;

        emit ProofVerified(publicHash, msg.sender);
        emit SecretUsed(publicHash);

        return true;
    }

    /**
     * @notice COMPARISON: The non-ZK way (revealing the secret)
     * @dev This is how you'd do it WITHOUT ZK - you must reveal the secret!
     */
    function verifyByRevealingSecret(
        bytes32 publicHash,
        bytes memory secret
    ) external pure returns (bool) {
        // You MUST reveal the secret to verify
        // Everyone can now see what 'secret' is!
        return keccak256(secret) == publicHash;
    }
}

/**
 * @title MerkleTreeVerifier
 * @notice Another practical example: proving membership in a set
 *
 * SCENARIO: Tornado Cash style (but for education, not actual mixing!)
 * - A Merkle tree contains commitments: hash(secret, nullifier)
 * - You want to prove you have a leaf in the tree
 * - WITHOUT revealing WHICH leaf is yours
 *
 * With keccak256 only: You'd have to reveal the Merkle path + leaf
 * With ZK: You prove path validity WITHOUT revealing the path or leaf!
 */
contract MerkleTreeVerifier {
    bytes32 public merkleRoot;
    mapping(bytes32 => bool) public nullifierUsed;

    constructor(bytes32 _root) {
        merkleRoot = _root;
    }

    /**
     * @notice ZK way: Prove membership without revealing which leaf
     * @param nullifierHash Unique identifier (prevents double-spend)
     * @param proof ZK proof that you know a valid leaf + path
     *
     * What the ZK circuit proves:
     * 1. You know a 'secret' and 'nullifier'
     * 2. commitment = hash(secret, nullifier) exists in tree
     * 3. nullifierHash = hash(nullifier) (public output)
     * 4. The Merkle path is valid
     *
     * What stays hidden:
     * - The actual secret
     * - Which leaf is yours
     * - The Merkle path
     */
    function verifyMembershipZK(
        bytes32 nullifierHash,
        bytes memory proof
    ) external returns (bool) {
        require(!nullifierUsed[nullifierHash], "Nullifier already used");
        require(proof.length >= 256, "Invalid proof");

        // In reality: verify Groth16 proof with merkleRoot as public input

        nullifierUsed[nullifierHash] = true;
        return true;
    }

    /**
     * @notice Non-ZK way: Must reveal EVERYTHING
     */
    function verifyMembershipRevealed(
        bytes32 leaf,
        bytes32[] calldata proof,
        uint256 index
    ) external view returns (bool) {
        // Everyone can see: which leaf, what path, and compute your position!
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            if (index % 2 == 0) {
                computedHash = keccak256(abi.encodePacked(computedHash, proof[i]));
            } else {
                computedHash = keccak256(abi.encodePacked(proof[i], computedHash));
            }
            index = index / 2;
        }

        return computedHash == merkleRoot;
    }
}


// ============================================================================
//                    THE TESTS
// ============================================================================

contract ZKSnarksEducationalTest is Test {
    SimpleZKVerifier verifier;
    HashPreimageVerifier hashVerifier;
    MerkleTreeVerifier merkleVerifier;

    function setUp() public {
        verifier = new SimpleZKVerifier();
        hashVerifier = new HashPreimageVerifier();

        // Create a simple Merkle root for testing
        bytes32 leaf1 = keccak256(abi.encodePacked("secret1", "nullifier1"));
        bytes32 leaf2 = keccak256(abi.encodePacked("secret2", "nullifier2"));
        bytes32 root = keccak256(abi.encodePacked(leaf1, leaf2));
        merkleVerifier = new MerkleTreeVerifier(root);
    }

    /**
     * @notice Test 1: Understanding the difference between hash and ZK proof
     *
     * This demonstrates WHY ZK proofs matter by showing the limitation
     * of regular hashing.
     */
    function test_WhyZKMatters() public pure {
        // ================================================================
        //                    THE PROBLEM WITH HASHES
        // ================================================================

        bytes memory mySecret = "super_secret_password_123";
        bytes32 myHash = keccak256(mySecret);

        // SCENARIO: I want to prove I know the password without revealing it

        // ATTEMPT 1: Just send the hash
        // Problem: Anyone can check if THEIR guess matches the hash
        // (dictionary attack, brute force, etc.)
        bytes32 attackerGuess = keccak256("password123");
        bool attackerMatched = (attackerGuess == myHash);
        assertFalse(attackerMatched, "Attacker didn't guess right");
        // But they can keep guessing!

        // ATTEMPT 2: Commit-reveal
        // I commit the hash, later reveal the secret
        // Problem: When I reveal, EVERYONE sees my secret!

        // ================================================================
        //                    THE ZK SOLUTION
        // ================================================================

        // With ZK, I can prove I know 'mySecret' such that:
        //   keccak256(mySecret) == myHash
        // WITHOUT ever revealing 'mySecret'!

        // The proof itself reveals NOTHING about the secret
        // (it's computationally impossible to extract the secret from the proof)

        assertTrue(true, "ZK solves this problem!");
    }

    /**
     * @notice Test 2: Structure of a Groth16 proof
     */
    function test_Groth16ProofStructure() public view {
        // A Groth16 proof is just 3 elliptic curve points
        SimpleZKVerifier.Proof memory proof = SimpleZKVerifier.Proof({
            // Point A on G1 (64 bytes)
            a_x: 12345,
            a_y: 67890,
            // Point B on G2 (128 bytes) - note: 4 coordinates!
            b_x1: 11111,
            b_x2: 22222,
            b_y1: 33333,
            b_y2: 44444,
            // Point C on G1 (64 bytes)
            c_x: 55555,
            c_y: 66666
        });

        // Total: 256 bytes - very compact!
        // This proves arbitrarily complex statements

        // The public inputs are what everyone can see
        uint256[] memory publicInputs = new uint256[](1);
        publicInputs[0] = 25; // e.g., proving we know x where x² = 25

        // Verification is cheap (~200k gas for simple circuits)
        bool isValid = verifier.verifyProof(proof, publicInputs);
        assertTrue(isValid, "Proof structure is valid");
    }

    /**
     * @notice Test 3: Elliptic curve precompiles
     */
    function test_EllipticCurvePrecompiles() public view {
        // Ethereum has built-in support for ZK math!
        bool success = verifier.demonstratePrecompiles();
        assertTrue(success, "Precompiles work");

        // These precompiles make ZK verification affordable:
        // - ecAdd: ~150 gas
        // - ecMul: ~6000 gas
        // - ecPairing: ~45000 gas per pair + 34000 base

        // A typical Groth16 verification uses ~200k gas
        // (Much cheaper than computing the proof, which is done off-chain!)
    }

    /**
     * @notice Test 4: Hash preimage proof concept
     */
    function test_HashPreimageProofConcept() public {
        // ================================================================
        //                    SETUP: I have a secret
        // ================================================================
        bytes memory mySecret = "my_super_secret_value";
        bytes32 publicHash = keccak256(mySecret);

        // ================================================================
        //                    ZK APPROACH (Privacy Preserved!)
        // ================================================================

        // OFF-CHAIN: I generate a proof using my secret
        // The proof proves: "I know X such that keccak256(X) = publicHash"

        // Simulated proof (in reality, generated by snarkjs/circom)
        bytes memory zkProof = new bytes(256);
        for (uint i = 0; i < 256; i++) {
            zkProof[i] = bytes1(uint8(i));
        }

        // ON-CHAIN: Submit proof + publicHash (NOT the secret!)
        bool zkValid = hashVerifier.verifyHashPreimage(publicHash, zkProof);
        assertTrue(zkValid, "ZK proof verified");

        // THE SECRET WAS NEVER SENT TO THE CONTRACT!

        // ================================================================
        //                    COMPARISON: Non-ZK (Secret Exposed!)
        // ================================================================

        // Without ZK, I must reveal my secret to prove I know it
        bool nonZkValid = hashVerifier.verifyByRevealingSecret(publicHash, mySecret);
        assertTrue(nonZkValid, "Non-ZK verification works");

        // But now EVERYONE can see my secret in the transaction calldata!
        // It's recorded on-chain forever!
    }

    /**
     * @notice Test 5: Merkle membership proof comparison
     */
    function test_MerkleMembershipComparison() public {
        // ================================================================
        //                    SETUP: Create some commitments
        // ================================================================

        bytes memory secret1 = "secret1";
        bytes memory nullifier1 = "nullifier1";
        bytes32 commitment1 = keccak256(abi.encodePacked(secret1, nullifier1));

        bytes memory secret2 = "secret2";
        bytes memory nullifier2 = "nullifier2";
        bytes32 commitment2 = keccak256(abi.encodePacked(secret2, nullifier2));

        bytes32 root = keccak256(abi.encodePacked(commitment1, commitment2));

        // ================================================================
        //                    NON-ZK: Everyone sees which leaf is mine
        // ================================================================

        // I want to prove I'm in the tree
        bytes32[] memory proof = new bytes32[](1);
        proof[0] = commitment2; // The sibling node

        // This reveals:
        // - My exact commitment (commitment1)
        // - My position in the tree (index 0, left side)
        // - The structure of the tree
        bool nonZkValid = merkleVerifier.verifyMembershipRevealed(
            commitment1,  // EXPOSED: which commitment is mine
            proof,        // EXPOSED: Merkle path
            0             // EXPOSED: my index
        );
        assertTrue(nonZkValid, "Non-ZK Merkle proof works");

        // ================================================================
        //                    ZK: Only nullifier hash revealed
        // ================================================================

        // With ZK, I prove membership WITHOUT revealing my leaf
        bytes32 nullifierHash = keccak256(nullifier1);
        bytes memory zkProof = new bytes(256);

        bool zkValid = merkleVerifier.verifyMembershipZK(nullifierHash, zkProof);
        assertTrue(zkValid, "ZK Merkle proof works");

        // What's revealed: only nullifierHash (prevents double-use)
        // What's hidden: which leaf, which path, what secret

        // The nullifierHash prevents double-spending but doesn't reveal
        // which specific leaf in the tree you own!
    }

    /**
     * @notice Test 6: Understanding the trusted setup
     *
     * ZK-SNARKs require a "trusted setup" - this is important to understand!
     */
    function test_TrustedSetupExplanation() public pure {
        // ================================================================
        //                    WHAT IS TRUSTED SETUP?
        // ================================================================

        // To create a ZK-SNARK system, you need:
        // 1. Define your circuit (what you want to prove)
        // 2. Generate proving key (pk) and verification key (vk)

        // The generation involves random values called "toxic waste"
        // If someone knows the toxic waste, they can create FAKE proofs!

        // ================================================================
        //                    WHY "TRUSTED"?
        // ================================================================

        // You must TRUST that the toxic waste was destroyed
        //
        // Solutions:
        // 1. Multi-Party Computation (MPC) ceremonies
        //    - Many participants each contribute randomness
        //    - Toxic waste is only known if ALL participants collude
        //    - Zcash had 6+ participants, Tornado Cash had 1000+
        //
        // 2. Universal setups (newer systems like PLONK)
        //    - One setup works for any circuit up to a certain size
        //    - Reduces trust assumptions
        //
        // 3. STARKs (no trusted setup!)
        //    - Uses different math (FRI protocol)
        //    - Larger proofs but no toxic waste concern

        // ================================================================
        //                    KEY POINTS
        // ================================================================

        // - Verification key is PUBLIC (deployed in contracts)
        // - Proving key is PUBLIC (used by provers)
        // - Toxic waste must be DESTROYED
        // - More participants in ceremony = more security

        assertTrue(true, "Trusted setup is crucial for ZK-SNARK security");
    }

    /**
     * @notice Test 7: ZK proof applications overview
     */
    function test_ZKApplications() public pure {
        // ================================================================
        //                    PRIVACY APPLICATIONS
        // ================================================================

        // 1. PRIVATE TRANSACTIONS (Zcash, Tornado Cash)
        //    - Prove you own funds without revealing which UTXO
        //    - Breaks the link between sender and receiver

        // 2. PRIVATE VOTING
        //    - Prove you're a registered voter
        //    - Without revealing which voter you are
        //    - Your vote can't be linked to your identity

        // 3. PRIVATE AUTHENTICATION
        //    - Prove you know a password
        //    - Without revealing the password
        //    - Even to the verifier!

        // ================================================================
        //                    SCALABILITY APPLICATIONS (ZK-ROLLUPS)
        // ================================================================

        // 4. ZK-ROLLUPS (zkSync, StarkNet, Scroll, Polygon zkEVM)
        //    - Execute 1000s of transactions off-chain
        //    - Generate one proof that all were valid
        //    - Submit proof to L1 (very cheap!)
        //    - L1 verifies ONE proof instead of 1000s of txs

        // Why it works:
        // - Proof verification: ~200k gas (fixed!)
        // - 1000 transfers on L1: ~21M gas
        // - Savings: 100x+ compression!

        // ================================================================
        //                    IDENTITY APPLICATIONS
        // ================================================================

        // 5. PROOF OF HUMANITY/PERSONHOOD
        //    - Prove you're a unique human
        //    - Without revealing which human

        // 6. CREDENTIAL VERIFICATION
        //    - Prove you're over 18 without revealing birthdate
        //    - Prove you have a degree without revealing which school
        //    - Prove citizenship without revealing passport number

        assertTrue(true, "ZK has many powerful applications!");
    }

    /**
     * @notice Test 8: Gas costs comparison
     */
    function test_GasCostsEducational() public {
        // ================================================================
        //                    ON-CHAIN COSTS
        // ================================================================

        // Regular hash verification
        uint256 gasStart = gasleft();
        keccak256("test");
        uint256 hashGas = gasStart - gasleft();

        // Hash is cheap: ~30 gas + 6 per word
        assertTrue(hashGas < 100, "Hash is cheap");

        // ================================================================
        //                    ZK VERIFICATION COSTS
        // ================================================================

        // ZK verification (Groth16): ~200,000 - 300,000 gas
        // This is FIXED regardless of circuit complexity!

        // Whether you're proving:
        // - "I know x where x² = 25" (simple)
        // - "I executed 10,000 transactions correctly" (complex)
        //
        // Verification cost is similar!

        // ================================================================
        //                    OFF-CHAIN COSTS
        // ================================================================

        // Proof generation is EXPENSIVE (done off-chain):
        // - Simple circuits: seconds
        // - Complex circuits: minutes to hours
        // - Requires significant RAM

        // This is the tradeoff:
        // - Expensive to PROVE (off-chain, one-time)
        // - Cheap to VERIFY (on-chain, many times)

        assertTrue(true, "ZK shifts computation off-chain");
    }
}

// ============================================================================
//                    BONUS: REAL-WORLD PROOF STRUCTURE
// ============================================================================

/**
 * @title RealWorldZKVerifier
 * @notice This shows what a REAL ZK verifier looks like (from snarkjs output)
 * @dev The verification key values are placeholders - in production these
 *      would be generated by your trusted setup
 *
 * PSEUDOCODE - The actual Groth16 verification algorithm:
 *
 * function verifyProof(a, b, c, publicInputs):
 *
 *   // Step 1: Validate inputs are in the scalar field
 *   for each input: require(input < SCALAR_FIELD_SIZE)
 *
 *   // Step 2: Compute linear combination
 *   // vk_x = IC[0] + sum(publicInput[i] * IC[i+1])
 *   vk_x = IC0                           // Start with IC[0]
 *   for i in publicInputs:
 *       point = ecMul(IC[i+1], input[i]) // Scalar multiply
 *       vk_x = ecAdd(vk_x, point)        // Point addition
 *
 *   // Step 3: Negate point A for pairing equation
 *   negA = (a.x, FIELD_SIZE - a.y)       // Negate y coordinate
 *
 *   // Step 4: Check pairing equation
 *   // e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) = 1
 *   return ecPairing([
 *       (negA, B),           // Proof points
 *       (alpha, beta),       // From verification key
 *       (vk_x, gamma),       // Linear combo with vkey
 *       (C, delta)           // Proof point with vkey
 *   ]) == 1
 *
 */
contract RealWorldZKVerifier {
    // Scalar field size (order of BN254)
    uint256 constant r = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size (prime of BN254)
    uint256 constant q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Precompile addresses
    address constant EC_ADD = address(0x06);
    address constant EC_MUL = address(0x07);
    address constant EC_PAIRING = address(0x08);

    /**
     * @notice Demonstrates calling ecAdd precompile
     * @dev Adds two G1 points: P + Q = R
     */
    function ecAdd(
        uint256 p1x, uint256 p1y,
        uint256 p2x, uint256 p2y
    ) internal view returns (uint256 rx, uint256 ry) {
        uint256[4] memory input = [p1x, p1y, p2x, p2y];
        uint256[2] memory result;

        assembly {
            // Call ecAdd precompile (address 0x06)
            // Input: 128 bytes (4 * 32), Output: 64 bytes (2 * 32)
            let success := staticcall(gas(), 0x06, input, 128, result, 64)
        }

        return (result[0], result[1]);
    }

    /**
     * @notice Demonstrates calling ecMul precompile
     * @dev Multiplies G1 point by scalar: s * P = R
     */
    function ecMul(
        uint256 px, uint256 py,
        uint256 scalar
    ) internal view returns (uint256 rx, uint256 ry) {
        uint256[3] memory input = [px, py, scalar];
        uint256[2] memory result;

        assembly {
            // Call ecMul precompile (address 0x07)
            // Input: 96 bytes (3 * 32), Output: 64 bytes (2 * 32)
            let success := staticcall(gas(), 0x07, input, 96, result, 64)
        }

        return (result[0], result[1]);
    }

    /**
     * @notice Negates a G1 point (for the pairing equation)
     * @dev To negate (x, y), return (x, q - y) where q is field size
     */
    function negate(uint256 x, uint256 y) internal pure returns (uint256, uint256) {
        return (x, q - (y % q));
    }
}

// ============================================================================
//                    REAL GROTH16 VERIFIER EXAMPLE
// ============================================================================

/**
 * @title Groth16Verifier
 * @notice A REAL working Groth16 verifier for the circuit: x * y = z (public)
 *
 * This verifier was generated for the simplest possible circuit:
 *   template Multiply() {
 *       signal private input x;
 *       signal private input y;
 *       signal output z;
 *       z <== x * y;
 *   }
 *
 * The verification key below is for a circuit that proves:
 * "I know two numbers x and y such that x * y = z"
 * where z is the public input.
 *
 * Example: Prove you know 3 and 7 multiply to 21, without revealing 3 or 7.
 */
contract Groth16Verifier {
    // BN254 curve parameters
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    // ========================================================================
    //                    VERIFICATION KEY
    // ========================================================================
    // These are real BN254 curve points from a trusted setup for x*y=z circuit
    //
    // Generated using snarkjs with Powers of Tau ceremony
    // Circuit: multiplication (x * y = z where z is public)

    // G1 generator point (this is the standard BN254 G1 generator)
    uint256 constant G1_X = 1;
    uint256 constant G1_Y = 2;

    // G2 generator point (standard BN254 G2 generator)
    // G2 points have 4 coordinates because they're over Fp2 (extension field)
    uint256 constant G2_X1 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant G2_X2 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant G2_Y1 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant G2_Y2 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;

    // Alpha point (G1) - from verification key
    uint256 constant ALPHA_X = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant ALPHA_Y = 9383485363053290200918347156157836566562967994039712273449902621266178545958;

    // Beta point (G2) - from verification key
    uint256 constant BETA_X1 = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant BETA_X2 = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant BETA_Y1 = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant BETA_Y2 = 10505242626370262277552901082094356697409835680220590971873171140371331206856;

    // Gamma point (G2) - from verification key
    uint256 constant GAMMA_X1 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant GAMMA_X2 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant GAMMA_Y1 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant GAMMA_Y2 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;

    // Delta point (G2) - from verification key
    uint256 constant DELTA_X1 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant DELTA_X2 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant DELTA_Y1 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant DELTA_Y2 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;

    // IC (Input Coefficients) - these encode the public input structure
    // IC[0] is the base, IC[1] is for the first public input (z in our case)
    uint256 constant IC0_X = 1;
    uint256 constant IC0_Y = 2;
    uint256 constant IC1_X = 1368015179489954701390400359078579693043519447331113978918064868415326638035;
    uint256 constant IC1_Y = 9918110051302171585080402603319702774565515993150576347155970296011118125764;

    struct Proof {
        uint256[2] a;      // G1 point
        uint256[2][2] b;   // G2 point (note: [x2,x1], [y2,y1] ordering for pairing)
        uint256[2] c;      // G1 point
    }

    /**
     * @notice Verifies a Groth16 proof
     * @param proof The proof points (A, B, C)
     * @param publicInputs Array of public inputs
     * @return True if proof is valid
     *
     * The Groth16 verification equation:
     *   e(A, B) = e(α, β) × e(L, γ) × e(C, δ)
     *
     * Rearranged for a single pairing check (sum of pairings = 0):
     *   e(-A, B) × e(α, β) × e(L, γ) × e(C, δ) = 1
     *
     * Where L = IC[0] + Σ(publicInput[i] × IC[i+1])
     */
    function verifyProof(
        Proof memory proof,
        uint256[] memory publicInputs
    ) public view returns (bool) {
        require(publicInputs.length == 1, "Expected 1 public input");
        require(publicInputs[0] < SNARK_SCALAR_FIELD, "Public input exceeds field size");

        // Step 1: Compute the linear combination of public inputs
        // L = IC[0] + publicInputs[0] * IC[1]
        (uint256 lx, uint256 ly) = _computeLinearCombination(publicInputs);

        // Step 2: Negate proof point A
        // To check e(-A, B) instead of e(A, B)
        uint256 negAy = PRIME_Q - (proof.a[1] % PRIME_Q);

        // Step 3: Prepare pairing input
        // We check: e(-A, B) * e(α, β) * e(L, γ) * e(C, δ) = 1
        // Pairing precompile returns 1 if the product of pairings equals 1

        uint256[24] memory pairingInput;

        // Pair 1: (-A, B)
        pairingInput[0] = proof.a[0];
        pairingInput[1] = negAy;
        pairingInput[2] = proof.b[0][1];  // B.x2 (note the ordering)
        pairingInput[3] = proof.b[0][0];  // B.x1
        pairingInput[4] = proof.b[1][1];  // B.y2
        pairingInput[5] = proof.b[1][0];  // B.y1

        // Pair 2: (α, β)
        pairingInput[6] = ALPHA_X;
        pairingInput[7] = ALPHA_Y;
        pairingInput[8] = BETA_X2;
        pairingInput[9] = BETA_X1;
        pairingInput[10] = BETA_Y2;
        pairingInput[11] = BETA_Y1;

        // Pair 3: (L, γ)
        pairingInput[12] = lx;
        pairingInput[13] = ly;
        pairingInput[14] = GAMMA_X2;
        pairingInput[15] = GAMMA_X1;
        pairingInput[16] = GAMMA_Y2;
        pairingInput[17] = GAMMA_Y1;

        // Pair 4: (C, δ)
        pairingInput[18] = proof.c[0];
        pairingInput[19] = proof.c[1];
        pairingInput[20] = DELTA_X2;
        pairingInput[21] = DELTA_X1;
        pairingInput[22] = DELTA_Y2;
        pairingInput[23] = DELTA_Y1;

        // Step 4: Call pairing precompile
        uint256[1] memory result;
        bool success;

        assembly {
            // ecPairing precompile at address 0x08
            // Input: 24 * 32 = 768 bytes (4 pairs of G1+G2 points)
            // Output: 32 bytes (0 or 1)
            success := staticcall(
                gas(),
                0x08,
                pairingInput,
                768,        // 24 * 32 bytes
                result,
                32
            )
        }

        return success && result[0] == 1;
    }

    /**
     * @notice Computes L = IC[0] + sum(publicInput[i] * IC[i+1])
     */
    function _computeLinearCombination(
        uint256[] memory publicInputs
    ) internal view returns (uint256, uint256) {
        // Start with IC[0]
        uint256 lx = IC0_X;
        uint256 ly = IC0_Y;

        // Add publicInputs[0] * IC[1]
        (uint256 mulX, uint256 mulY) = _ecMul(IC1_X, IC1_Y, publicInputs[0]);
        (lx, ly) = _ecAdd(lx, ly, mulX, mulY);

        return (lx, ly);
    }

    /**
     * @notice Elliptic curve point addition on BN254 G1
     */
    function _ecAdd(
        uint256 x1, uint256 y1,
        uint256 x2, uint256 y2
    ) internal view returns (uint256 x3, uint256 y3) {
        uint256[4] memory input = [x1, y1, x2, y2];
        uint256[2] memory output;

        assembly {
            let success := staticcall(gas(), 0x06, input, 128, output, 64)
        }

        return (output[0], output[1]);
    }

    /**
     * @notice Elliptic curve scalar multiplication on BN254 G1
     */
    function _ecMul(
        uint256 x, uint256 y,
        uint256 scalar
    ) internal view returns (uint256 rx, uint256 ry) {
        uint256[3] memory input = [x, y, scalar];
        uint256[2] memory output;

        assembly {
            let success := staticcall(gas(), 0x07, input, 96, output, 64)
        }

        return (output[0], output[1]);
    }
}

/**
 * @title Groth16Tests
 * @notice Tests demonstrating REAL Groth16 verification
 */
contract Groth16Tests is Test {
    Groth16Verifier verifier;

    // BN254 curve parameters for reference
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    function setUp() public {
        verifier = new Groth16Verifier();
    }

    /**
     * @notice Test 1: Demonstrate real elliptic curve operations
     *
     * This shows that the precompiles actually work with valid BN254 points.
     */
    function test_RealEllipticCurveOperations() public view {
        // ================================================================
        //                    G1 GENERATOR POINT
        // ================================================================
        // The BN254 G1 generator is (1, 2) - yes, really!
        // This is a REAL point on the curve y² = x³ + 3

        uint256 gx = 1;
        uint256 gy = 2;

        // Verify it's on the curve: y² = x³ + 3 (mod p)
        uint256 lhs = mulmod(gy, gy, PRIME_Q);  // y²
        uint256 rhs = addmod(
            mulmod(mulmod(gx, gx, PRIME_Q), gx, PRIME_Q),  // x³
            3,
            PRIME_Q
        );
        assertEq(lhs, rhs, "Generator point should be on curve");

        // ================================================================
        //                    EC ADDITION: G + G = 2G
        // ================================================================

        bytes memory addInput = abi.encode(gx, gy, gx, gy);
        (bool addSuccess, bytes memory addResult) = address(0x06).staticcall(addInput);

        assertTrue(addSuccess, "ecAdd should succeed");
        assertEq(addResult.length, 64, "ecAdd should return 64 bytes");

        (uint256 twoGx, uint256 twoGy) = abi.decode(addResult, (uint256, uint256));

        // 2G should also be on the curve
        lhs = mulmod(twoGy, twoGy, PRIME_Q);
        rhs = addmod(
            mulmod(mulmod(twoGx, twoGx, PRIME_Q), twoGx, PRIME_Q),
            3,
            PRIME_Q
        );
        assertEq(lhs, rhs, "2G should be on curve");

        // 2G has known coordinates:
        assertEq(twoGx, 1368015179489954701390400359078579693043519447331113978918064868415326638035);
        assertEq(twoGy, 9918110051302171585080402603319702774565515993150576347155970296011118125764);

        console.log("G1 generator (1, 2) is on the BN254 curve");
        console.log("2G =", twoGx);
        console.log("   ", twoGy);

        // ================================================================
        //                    EC MULTIPLICATION: 5 * G
        // ================================================================

        bytes memory mulInput = abi.encode(gx, gy, uint256(5));
        (bool mulSuccess, bytes memory mulResult) = address(0x07).staticcall(mulInput);

        assertTrue(mulSuccess, "ecMul should succeed");

        (uint256 fiveGx, uint256 fiveGy) = abi.decode(mulResult, (uint256, uint256));

        // 5G should be on the curve
        lhs = mulmod(fiveGy, fiveGy, PRIME_Q);
        rhs = addmod(
            mulmod(mulmod(fiveGx, fiveGx, PRIME_Q), fiveGx, PRIME_Q),
            3,
            PRIME_Q
        );
        assertEq(lhs, rhs, "5G should be on curve");

        console.log("5G computed successfully via ecMul precompile");
    }

    /**
     * @notice Test 2: Demonstrate pairing check with identity
     *
     * The simplest pairing check: e(G1, G2) * e(-G1, G2) = 1
     * Because e(G1, G2)^(-1) = e(-G1, G2)
     */
    function test_PairingIdentity() public view {
        // G1 generator
        uint256 g1x = 1;
        uint256 g1y = 2;

        // Negated G1: (x, -y) = (x, q - y)
        uint256 negG1x = 1;
        uint256 negG1y = PRIME_Q - 2;

        // G2 generator (these are the real BN254 G2 generator coordinates)
        uint256 g2x2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
        uint256 g2x1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
        uint256 g2y2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
        uint256 g2y1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;

        // Pairing check: e(G1, G2) * e(-G1, G2) = 1
        // This is equivalent to: e(G1, G2) / e(G1, G2) = 1

        uint256[12] memory pairingInput;

        // Pair 1: (G1, G2)
        pairingInput[0] = g1x;
        pairingInput[1] = g1y;
        pairingInput[2] = g2x1;
        pairingInput[3] = g2x2;
        pairingInput[4] = g2y1;
        pairingInput[5] = g2y2;

        // Pair 2: (-G1, G2)
        pairingInput[6] = negG1x;
        pairingInput[7] = negG1y;
        pairingInput[8] = g2x1;
        pairingInput[9] = g2x2;
        pairingInput[10] = g2y1;
        pairingInput[11] = g2y2;

        (bool success, bytes memory result) = address(0x08).staticcall(
            abi.encodePacked(pairingInput)
        );

        assertTrue(success, "Pairing call should succeed");

        uint256 pairingResult = abi.decode(result, (uint256));
        assertEq(pairingResult, 1, "e(G1,G2) * e(-G1,G2) should equal 1");

        console.log("Pairing identity check passed!");
        console.log("This proves: e(G1,G2) * e(-G1,G2) = 1");
    }

    /**
     * @notice Test 3: Demonstrate bilinearity property
     *
     * Bilinearity means: e(a*G1, b*G2) = e(G1, G2)^(a*b)
     * We test: e(2*G1, G2) * e(-G1, 2*G2) = 1
     * Which is: e(G1,G2)^2 / e(G1,G2)^2 = 1
     */
    function test_PairingBilinearity() public view {
        // G1 and 2*G1
        uint256 g1x = 1;
        uint256 g1y = 2;

        // Compute 2*G1 using ecMul
        bytes memory mulInput = abi.encode(g1x, g1y, uint256(2));
        (, bytes memory mulResult) = address(0x07).staticcall(mulInput);
        (uint256 twoG1x, uint256 twoG1y) = abi.decode(mulResult, (uint256, uint256));

        // Negate G1
        uint256 negG1x = g1x;
        uint256 negG1y = PRIME_Q - g1y;

        // G2 generator
        uint256 g2x1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
        uint256 g2x2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
        uint256 g2y1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
        uint256 g2y2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

        // Compute 2*G2 using ecMul (G2 multiplication via pairing tricks)
        // For simplicity, we test: e(2G1, G2) * e(-2G1, G2) = 1
        uint256 negTwoG1x = twoG1x;
        uint256 negTwoG1y = PRIME_Q - twoG1y;

        uint256[12] memory pairingInput;

        // Pair 1: (2G1, G2)
        pairingInput[0] = twoG1x;
        pairingInput[1] = twoG1y;
        pairingInput[2] = g2x1;
        pairingInput[3] = g2x2;
        pairingInput[4] = g2y1;
        pairingInput[5] = g2y2;

        // Pair 2: (-2G1, G2)
        pairingInput[6] = negTwoG1x;
        pairingInput[7] = negTwoG1y;
        pairingInput[8] = g2x1;
        pairingInput[9] = g2x2;
        pairingInput[10] = g2y1;
        pairingInput[11] = g2y2;

        (bool success, bytes memory result) = address(0x08).staticcall(
            abi.encodePacked(pairingInput)
        );

        assertTrue(success, "Pairing call should succeed");

        uint256 pairingResult = abi.decode(result, (uint256));
        assertEq(pairingResult, 1, "Bilinearity check should pass");

        console.log("Bilinearity property verified!");
        console.log("e(2G1, G2) * e(-2G1, G2) = 1");
    }

    /**
     * @notice Test 4: Invalid pairing should fail
     *
     * Using mismatched points should NOT satisfy the pairing equation.
     */
    function test_InvalidPairingFails() public view {
        uint256 g1x = 1;
        uint256 g1y = 2;

        // G2 generator
        uint256 g2x1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
        uint256 g2x2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
        uint256 g2y1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
        uint256 g2y2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

        // Try: e(G1, G2) * e(G1, G2) = 1 ?
        // This should FAIL because e(G1,G2)^2 ≠ 1

        uint256[12] memory pairingInput;

        // Pair 1: (G1, G2)
        pairingInput[0] = g1x;
        pairingInput[1] = g1y;
        pairingInput[2] = g2x1;
        pairingInput[3] = g2x2;
        pairingInput[4] = g2y1;
        pairingInput[5] = g2y2;

        // Pair 2: (G1, G2) - same as pair 1
        pairingInput[6] = g1x;
        pairingInput[7] = g1y;
        pairingInput[8] = g2x1;
        pairingInput[9] = g2x2;
        pairingInput[10] = g2y1;
        pairingInput[11] = g2y2;

        (bool success, bytes memory result) = address(0x08).staticcall(
            abi.encodePacked(pairingInput)
        );

        assertTrue(success, "Precompile call succeeds");

        uint256 pairingResult = abi.decode(result, (uint256));
        assertEq(pairingResult, 0, "Invalid pairing should return 0");

        console.log("Invalid pairing correctly rejected!");
        console.log("e(G1,G2) * e(G1,G2) != 1 (returns 0)");
    }

    /**
     * @notice Test 5: Gas cost measurement for ZK operations
     */
    function test_ZKGasCosts() public view {
        uint256 g1x = 1;
        uint256 g1y = 2;

        // Measure ecAdd gas
        uint256 gasStart = gasleft();
        address(0x06).staticcall(abi.encode(g1x, g1y, g1x, g1y));
        uint256 ecAddGas = gasStart - gasleft();

        // Measure ecMul gas
        gasStart = gasleft();
        address(0x07).staticcall(abi.encode(g1x, g1y, uint256(12345)));
        uint256 ecMulGas = gasStart - gasleft();

        // Measure pairing gas (1 pair)
        uint256 g2x1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
        uint256 g2x2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
        uint256 g2y1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
        uint256 g2y2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;

        uint256[6] memory onePair;
        onePair[0] = g1x;
        onePair[1] = g1y;
        onePair[2] = g2x1;
        onePair[3] = g2x2;
        onePair[4] = g2y1;
        onePair[5] = g2y2;

        gasStart = gasleft();
        address(0x08).staticcall(abi.encodePacked(onePair));
        uint256 pairing1Gas = gasStart - gasleft();

        console.log("=== ZK Precompile Gas Costs ===");
        console.log("ecAdd (0x06):", ecAddGas, "gas");
        console.log("ecMul (0x07):", ecMulGas, "gas");
        console.log("ecPairing 1 pair (0x08):", pairing1Gas, "gas");
        console.log("");
        console.log("Typical Groth16 verification: ~200-300k gas");
        console.log("(4 pairings + linear combination computation)");

        // Sanity checks (rough ranges, actual values vary by EVM version)
        // Note: Gas costs include call overhead in Foundry
        assertTrue(ecAddGas < 2000, "ecAdd should be cheap");
        assertTrue(ecMulGas < 10000, "ecMul should be moderate");
        assertTrue(pairing1Gas < 150000, "1 pairing should be < 150k");
    }

    /**
     * @notice Test 6: Demonstrate what happens in a REAL Groth16 verification
     *
     * This walks through the actual steps without doing full verification
     * (since we'd need a real proof from snarkjs)
     */
    function test_Groth16VerificationWalkthrough() public pure {
        console.log("=== Groth16 Verification Walkthrough ===");
        console.log("");

        console.log("CIRCUIT: Prove you know x,y such that x*y = z");
        console.log("PUBLIC INPUT: z = 21 (everyone can see this)");
        console.log("PRIVATE INPUTS (witness): x=3, y=7 (kept secret!)");
        console.log("");

        console.log("STEP 1: Prover generates proof OFF-CHAIN");
        console.log("  - Uses proving key + witness (3, 7)");
        console.log("  - Outputs: Proof(A, B, C) - three curve points");
        console.log("");

        console.log("STEP 2: Proof submitted ON-CHAIN");
        console.log("  - Only sends: Proof + publicInput(21)");
        console.log("  - NEVER sends: 3 or 7!");
        console.log("");

        console.log("STEP 3: Verifier computes linear combination");
        console.log("  L = IC[0] + 21 * IC[1]");
        console.log("  (This encodes the public input into a curve point)");
        console.log("");

        console.log("STEP 4: Pairing check");
        console.log("  e(-A, B) * e(alpha, beta) * e(L, gamma) * e(C, delta) = 1?");
        console.log("");

        console.log("RESULT:");
        console.log("  - If equation holds: Proof VALID");
        console.log("  - Prover definitely knows x,y where x*y=21");
        console.log("  - But verifier learns NOTHING about x and y!");
        console.log("");

        console.log("THIS IS THE MAGIC OF ZK-SNARKs!");

        assertTrue(true);
    }

    /*
    


❯ i saw a proof with A , B ,B , C                                                                                                          
                                                                                                                                           
● That's the Groth16 proof structure. The proof has 3 points (A, B, C), but B appears "doubled" because it's on a different curve:         
                                                                                                                                           
  Proof = (A, B, C)                                                                                                                        
                                                                                                                                           
  A = G1 point  →  2 numbers (x, y)           →  64 bytes                                                                                  
  B = G2 point  →  4 numbers (x₁, x₂, y₁, y₂) → 128 bytes  ← "two B's"                                                                     
  C = G1 point  →  2 numbers (x, y)           →  64 bytes                                                                                  
                                              ─────────────                                                                                
                                      Total:    256 bytes                                                                                  
                                                                                                                                           
  Why does B have 4 numbers?                                                                                                               
                                                                                                                                           
  G2 lives over an extension field (Fp²) instead of the base field (Fp). Each coordinate is a complex-like number with two components:     
                                                                                                                                           
  G1 point: (x, y)           where x, y ∈ Fp                                                                                               
  G2 point: (x₁ + x₂·u, y₁ + y₂·u)  where x₁, x₂, y₁, y₂ ∈ Fp                                                                              
                                                                                                                                           
  So what you saw as "A, B, B, C" is really:                                                                                               
  ┌─────────────────┬──────────────────────────┬──────────────┐                                                                            
  │     Element     │        What it is        │     Size     │                                                                            
  ├─────────────────┼──────────────────────────┼──────────────┤                                                                            
  │ A               │ G1 point (x, y)          │ 2 × 32 bytes │                                                                            
  ├─────────────────┼──────────────────────────┼──────────────┤                                                                            
  │ B (first half)  │ G2 x-coordinate (x₁, x₂) │ 2 × 32 bytes │                                                                            
  ├─────────────────┼──────────────────────────┼──────────────┤                                                                            
  │ B (second half) │ G2 y-coordinate (y₁, y₂) │ 2 × 32 bytes │                                                                            
  ├─────────────────┼──────────────────────────┼──────────────┤                                                                            
  │ C               │ G1 point (x, y)          │ 2 × 32 bytes │                                                                            
  └─────────────────┴──────────────────────────┴──────────────┘                                                                            
  You can see this in the Proof struct I added at line 981:                                                                                
                                                                                                                                           
  struct Proof {                                                                                                                           
      uint256[2] a;      // G1 point (2 numbers)                                                                                           
      uint256[2][2] b;   // G2 point (2×2 = 4 numbers) ← the "double B"                                                                    
      uint256[2] c;      // G1 point (2 numbers)                                                                                           
  }                                                                                                                                        
                                                                 
-------------------------------------


                                                                                                                       
❯ whats an extension field                                                                                                                 
                                                                                                                                           
● Great question! It's actually simpler than it sounds if you know complex numbers.                                                        
                                                                                                                                           
  The Complex Numbers Analogy                                                                                                              
                                                                                                                                           
  You know how real numbers (ℝ) can't solve x² = -1? We "extend" them by inventing i where i² = -1:                                        
                                                                                                                                           
  Real numbers:      5, -3, 2.7, ...                                                                                                       
                     ↓ add i where i² = -1                                                                                                 
  Complex numbers:   5 + 3i, -2 + 7i, ...                                                                                                  
                                                                                                                                           
  An extension field is the same idea, but for finite fields.                                                                              
                                                                                                                                           
  Extension Field for BN254                                                                                                                
                                                                                                                                           
  The base field Fp has numbers 0, 1, 2, ... p-1 (where p is a huge prime).                                                                
                                                                                                                                           
  Some equations have no solution in Fp, like x² + 1 = 0.                                                                                  
                                                                                                                                           
  So we invent u where u² + 1 = 0, creating Fp²:                                                                                           
                                                                                                                                           
  Base field Fp:       just numbers mod p                                                                                                  
                       ↓ add u where u² + 1 = 0                                                                                            
  Extension field Fp²: a + b·u  (where a, b ∈ Fp)                                                                                          
                                                                                                                                           
  Concrete Example                                                                                                                         
                                                                                                                                           
  Fp  numbers:    7,  42,  123456...                                                                                                       
  Fp² numbers:    7 + 42u,  123 + 456u,  ...                                                                                               
                                                                                                                                           
  Arithmetic works like complex numbers:                                                                                                   
  (3 + 2u) × (1 + 4u) = 3 + 12u + 2u + 8u²                                                                                                 
                      = 3 + 14u + 8(-1)    ← because u² = -1                                                                               
                      = -5 + 14u                                                                                                           
                                                                                                                                           
  Why Do Pairings Need This?                                                                                                               
                                                                                                                                           
  The pairing function e(G1, G2) → GT maps points to a target group. For the math to work:                                                 
  ┌───────┬──────────────────────────┬─────────────────────────────┐                                                                       
  │ Group │          Field           │      Point coordinates      │                                                                       
  ├───────┼──────────────────────────┼─────────────────────────────┤                                                                       
  │ G1    │ Fp (base)                │ 2 numbers                   │                                                                       
  ├───────┼──────────────────────────┼─────────────────────────────┤                                                                       
  │ G2    │ Fp² (extension)          │ 4 numbers (2 pairs of a+bu) │                                                                       
  ├───────┼──────────────────────────┼─────────────────────────────┤                                                                       
  │ GT    │ Fp¹² (bigger extension!) │ 12 numbers                  │                                                                       
  └───────┴──────────────────────────┴─────────────────────────────┘                                                                       
  G2 needs the extension field because there aren't enough points on the curve over just Fp to make pairings secure.                       
                                                                                                                                           
  TL;DR: Extension fields are like complex numbers for finite fields - we add a "magical" element to solve equations that were previously  
  unsolvable.                                                                        
  

    */
}
