// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

contract Sample {
    mapping(address => uint) public balances;

    // Function to deposit ether into the contract
    function deposit() public payable {
        // Vulnerability: Disable overflow/underflow check
        unchecked {
            balances[msg.sender] += msg.value;
        }
    }

    // Function to withdraw balance from the contract
    function withdraw() public {
        uint amount = balances[msg.sender];
        
        require(amount > 0, "Insufficient balance");

        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed.");

        balances[msg.sender] = 0;
    }

    function getBalance() public view returns (uint) {
        return balances[msg.sender];
    }
}
