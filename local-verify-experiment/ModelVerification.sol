// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ModelVerification {
    struct ClientData {
        string signature;
        uint256 modelQualityScore; // store the score as uint256 for simplicity (scaled float)
        bool hasSubmitted; // track if client already submitted
    }

    mapping(address => ClientData) public clients;
    address[] public clientAddresses;
    uint256 public totalClients;
    address public firstClient; // the first client to submit
    uint256 public threshold; // threshold for score comparison

    event Endorsement(string[] signatures, uint256 firstClientScore);
    event Warning(string message);

    constructor(uint256 _totalClients, uint256 _threshold) {
        require(_totalClients > 1, "need more than 1 client");
        totalClients = _totalClients;
        threshold = _threshold;
    }

    function submitData(string memory _signature, uint256 _modelQualityScore) public {
        require(!clients[msg.sender].hasSubmitted, "already submitted");
        require(clientAddresses.length < totalClients, "all submissions done");

        // check if this is the first client
        if (clientAddresses.length == 0) {
            firstClient = msg.sender;
        }

        clients[msg.sender] = ClientData({
            signature: _signature,
            modelQualityScore: _modelQualityScore,
            hasSubmitted: true
        });

        clientAddresses.push(msg.sender);

        // if all clients submitted, run evaluation
        if (clientAddresses.length == totalClients) {
            evaluateModel();
        }
    }

    function evaluateModel() internal {
        require(clientAddresses.length == totalClients, "not everyone submitted");

        uint256 firstClientScore = clients[firstClient].modelQualityScore;
        uint256 agreementCount = 0;

        // loop through other clients and compare their scores
        for (uint256 i = 1; i < clientAddresses.length; i++) {
            uint256 clientScore = clients[clientAddresses[i]].modelQualityScore;
            if (
                clientScore >= firstClientScore - threshold &&
                clientScore <= firstClientScore + threshold
            ) {
                agreementCount++;
            }
        }

        // decide whether to endorse or warn
        if (agreementCount > (totalClients - 1) / 2) {
            // collect all signatures
            string[] memory signatures = new string[](totalClients);
            for (uint256 i = 0; i < clientAddresses.length; i++) {
                signatures[i] = clients[clientAddresses[i]].signature;
            }
            emit Endorsement(signatures, firstClientScore);
        } else {
            // emit warning
            emit Warning("not enough agreement on the score");
        }
    }
}
