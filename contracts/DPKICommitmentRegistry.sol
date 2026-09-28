// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

contract DPKICommitmentRegistry {
    address public owner;

    struct Commitment {
        bytes32 root;
        uint64 version;
        uint64 certificateCount;
        uint64 revokedCount;
        uint64 updatedAt;
    }

    struct PendingCommitment {
        bytes32 root;
        uint64 certificateCount;
        uint64 revokedCount;
        address updater;
        bool exists;
    }

    mapping(address => bool) public authorizedUpdater;
    mapping(address => bool) public authorizedValidator;
    mapping(bytes32 => Commitment) private latestCommitment;
    mapping(bytes32 => PendingCommitment) private pendingCommitment;

    event UpdaterAuthorizationChanged(address indexed updater, bool authorized);
    event ValidatorAuthorizationChanged(address indexed validator, bool authorized);
    event CommitmentProposed(bytes32 indexed domainId, bytes32 indexed root,
        uint64 certificateCount, uint64 revokedCount, address indexed updater);
    event CommitmentUpdated(bytes32 indexed domainId, bytes32 indexed root,
        uint64 version, uint64 certificateCount, uint64 revokedCount,
        uint64 updatedAt, address updater, address validator);

    modifier onlyOwner() { require(msg.sender == owner, "not owner"); _; }
    modifier onlyUpdater() { require(authorizedUpdater[msg.sender], "not authorized updater"); _; }
    modifier onlyValidator() { require(authorizedValidator[msg.sender], "not authorized validator"); _; }

    constructor() {
        owner = msg.sender;
        authorizedUpdater[msg.sender] = true;
    }

    function setUpdater(address updater, bool authorized) external onlyOwner {
        require(updater != address(0), "zero address");
        authorizedUpdater[updater] = authorized;
        emit UpdaterAuthorizationChanged(updater, authorized);
    }

    function setValidator(address validator, bool authorized) external onlyOwner {
        require(validator != address(0), "zero address");
        authorizedValidator[validator] = authorized;
        emit ValidatorAuthorizationChanged(validator, authorized);
    }

    // Step 1: DCM/updater proposes C_D. This is not yet an anchored commitment.
    function proposeCommitment(bytes32 domainId, bytes32 root,
        uint64 certificateCount, uint64 revokedCount) external onlyUpdater {
        require(domainId != bytes32(0), "empty domain");
        require(root != bytes32(0), "empty root");
        require(revokedCount <= certificateCount, "bad counts");
        require(!pendingCommitment[domainId].exists, "proposal already pending");

        pendingCommitment[domainId] = PendingCommitment(
            root, certificateCount, revokedCount, msg.sender, true
        );
        emit CommitmentProposed(domainId, root, certificateCount, revokedCount, msg.sender);
    }

    // Step 2: an independent validator submits C_V reconstructed off-chain.
    // The commitment is anchored only when C_D == C_V.
    function validateAndCommit(bytes32 domainId, bytes32 validatedRoot)
        external onlyValidator returns (uint64 newVersion) {
        require(validatedRoot != bytes32(0), "empty validated root");
        PendingCommitment memory pending = pendingCommitment[domainId];
        require(pending.exists, "no pending proposal");

        require(pending.root == validatedRoot, "commitment validation failed");

        Commitment storage current = latestCommitment[domainId];
        newVersion = current.version + 1;
        uint64 timestamp = uint64(block.timestamp);
        latestCommitment[domainId] = Commitment(
            pending.root, newVersion, pending.certificateCount,
            pending.revokedCount, timestamp
        );
        delete pendingCommitment[domainId];
        emit CommitmentUpdated(domainId, pending.root, newVersion,
            pending.certificateCount, pending.revokedCount, timestamp,
            pending.updater, msg.sender);
    }

    function cancelPendingCommitment(bytes32 domainId) external onlyUpdater {
        PendingCommitment memory pending = pendingCommitment[domainId];
        require(pending.exists, "no pending proposal");
        require(pending.updater == msg.sender, "not proposal updater");
        delete pendingCommitment[domainId];
    }

    function getPendingCommitment(bytes32 domainId) external view returns (
        bytes32 root, uint64 certificateCount, uint64 revokedCount,
        address updater, bool exists) {
        PendingCommitment memory p = pendingCommitment[domainId];
        return (p.root, p.certificateCount, p.revokedCount, p.updater, p.exists);
    }

    function getCommitment(bytes32 domainId) external view returns (
        bytes32 root, uint64 version, uint64 certificateCount,
        uint64 revokedCount, uint64 updatedAt) {
        Commitment memory c = latestCommitment[domainId];
        return (c.root, c.version, c.certificateCount, c.revokedCount, c.updatedAt);
    }
}
