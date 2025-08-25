// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

contract SimplePaymentChannel{
    address immutable SENDER;
    address payable immutable RECEIVER;
    uint expiration;
    bool private closed;

    constructor(address _receiver, uint _duration)payable{
        SENDER = msg.sender;
        RECEIVER = payable(_receiver);
        expiration = block.timestamp + _duration;
    }

    function prefixed(bytes32 hash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function isValidSignature(uint amount, bytes memory signature) public view returns(bool) {
        bytes32 message = prefixed(keccak256(abi.encodePacked(address(this), amount)));

        // check if SENDER has signed the message
        return recoverSigner(message, signature) == SENDER;
    }

    function close(uint amount, bytes memory signature) public {
        require(msg.sender == RECEIVER, "Only receiver can close payment channel!");
        require(block.timestamp < expiration, "Channel duration expired!");
        require(isValidSignature(amount, signature), "Invalid signature");
        require(!closed, "Channel already closed");

        closed = true;

        (bool sent, ) = RECEIVER.call{value: amount}("");
        require(sent, "Failed to send ETH");

        selfdestruct(payable(SENDER));
    }

    // If the timeout is reached without the receipient closing the channel, then the ether is released back to sender.
    function claimTimeout() external {
        // require(msg.sender == SENDER, "Only send")
        require(block.timestamp >= expiration, "Channel has not expired yet!");

        selfdestruct(payable(SENDER));
    }

    function extendExpiration(uint _duration) external {
        require(msg.sender == SENDER, "Only sender can extend expiration!");
        // require(EXPIRATION < _duration, "Extend time ")

        // extend by 1 day/week/month/year
        expiration = block.timestamp + _duration;
    }

    function recoverSigner(bytes32 message, bytes memory signature) public pure returns (address) {
        (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);

        return ecrecover(message, v,r,s);
    }

    function splitSignature(bytes memory sig) public pure returns(uint8 v, bytes32 r, bytes32 s){
        require(sig.length == 65, "Invalid signature length");

        assembly{
            r:= mload(add(sig,32))
            s:= mload(add(sig, 64))
            v:= byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        require(v == 27 || v == 28, "bad v");

        // EIP-2: s must be in lower half
        require(uint256(s) <= 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, "bad s");
    }
}

// sepolia: 0xC573C58EfFCdE6f66034566Be7f00153082cE2DB