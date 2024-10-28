// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

contract Sample {
    mapping(address => uint) public balances;

    // Function to deposit ether into the contract
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerable function with reentrancy risk
    function withdraw() public {
        uint amount = balances[msg.sender];

        // Check that the balance is sufficient
        require(amount > 0, "Insufficient balance");

        // Vulnerability: The balance update happens after the external call
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed.");

        // The balance is set after the call (reentrancy risk)
        balances[msg.sender] = 0;
    }

    // Function to get the balance of the caller
    function getBalance() public view returns (uint) {
        return balances[msg.sender];
    }
}
