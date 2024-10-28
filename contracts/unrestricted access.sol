// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

contract Sample {
    mapping(address => uint) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Function to deposit ether into the contract
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // Vulnerability: No access control, anyone can call this function
    function withdrawAll() public {
        // Sends all contract balance to the caller, but no access control
        (bool success, ) = msg.sender.call{value: address(this).balance}("");
        require(success, "Transfer failed.");
    }

    function getBalance() public view returns (uint) {
        return balances[msg.sender];
    }
}
    