// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ModelVerification {
    struct ClientData {
        string signature;
        bool clusterVerification;
        bool modelVerification;
        uint256 modelQualityScore; // Storing as uint256 for simplicity (scaled float)
        bool hasSubmitted; // To track whether the client has already submitted
    }

    mapping(address => ClientData) public clients;
    address[] public clientAddresses;
    uint256 public totalClients;
    uint256 public totalModelQualityScore; // Sum of scores for majority votes
    uint256 public positiveVotes;

    event Endorsement(string[] signatures, uint256 computedThreshold);

    constructor(uint256 _totalClients) {
        require(_totalClients > 0, "Total clients must be greater than 0");
        totalClients = _totalClients;
    }

    function submitData(
        string memory _signature,
        bool _clusterVerification,
        bool _modelVerification,
        uint256 _modelQualityScore
    ) public {
        require(!clients[msg.sender].hasSubmitted, "Already submitted");

        clients[msg.sender] = ClientData({
            signature: _signature,
            clusterVerification: _clusterVerification,
            modelVerification: _modelVerification,
            modelQualityScore: _modelQualityScore,
            hasSubmitted: true
        });

        clientAddresses.push(msg.sender);

        if (_modelVerification) {
            positiveVotes++;
            totalModelQualityScore += _modelQualityScore;
        }

        // If all clients have submitted, evaluate
        if (clientAddresses.length == totalClients) {
            evaluateModel();
        }
    }

    function evaluateModel() internal {
        require(clientAddresses.length == totalClients, "Not all clients submitted");

        // Compute the average score from majority votes
        if (positiveVotes > totalClients / 2 && positiveVotes > 0) {
            uint256 averageQualityScore = totalModelQualityScore / positiveVotes;

            // Emit endorsement with computed threshold
            string[] memory signatures = new string[](totalClients);
            for (uint256 i = 0; i < clientAddresses.length; i++) {
                signatures[i] = clients[clientAddresses[i]].signature;
            }

            emit Endorsement(signatures, averageQualityScore);
        }
    }
}