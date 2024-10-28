// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

contract Sample {
    mapping(address => uint) public balances;

    // Function to deposit ether into the contract
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Function to withdraw balance from the contract
    function withdraw() public {
        uint amount = balances[msg.sender];
        
        // Check that the balance is sufficient
        require(amount > 0, "Insufficient balance");

        // Vulnerability: Low-level call without checking return value
        msg.sender.call{value: amount}("");  // No require(success) statement

        balances[msg.sender] = 0;
    }

    // Function to get the balance of the caller
    function getBalance() public view returns (uint) {
        return balances[msg.sender];
    }
}
