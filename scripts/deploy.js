const hre = require("hardhat");

async function main() {
    const Contract = await hre.ethers.getContractFactory("Reentrancy"); // Change this to match your contract name
    const contract = await Contract.deploy(); // Add constructor arguments if needed

    await contract.deployed();
    console.log(`Contract deployed to: ${contract.address}`);
}

main().catch((error) => {
    console.error(error);
    process.exit(1);
});

