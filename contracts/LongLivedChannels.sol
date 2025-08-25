// SPDX-License-Identifier: MIT
pragma solidity ^0.8;

contract LongLivedPaymentChannel {
    address public immutable SENDER;
    address public immutable RECIPIENT;
    uint public withdrawn;  // How much the recipient has already withdrawn.

    // How much time recipient has to respond when the sender initiates the channel closure.
    uint public closeDuration;

    // When the payment channel closes, Initially effectively infinite
    uint public expiration = 2 ** 256 - 1;

    constructor(address _recipient, uint _closeDuration) {
        RECIPIENT = _recipient;
        SENDER = msg.sender;
        closeDuration = _closeDuration;
    }

    function isValidSignature(uint amount, bytes memory signature) public view returns(bool) {
        bytes32 messageHash = prefixed(keccak256(abi.encodePacked(address(this), amount)));

        return recoverSigner(messageHash, signature) == SENDER;
    }

    // The recipient can close the channel any time by presenting signed amount from the sender.
    // The recipient will get his amount and rest will go back to sender.
    function close(uint amount, bytes memory signature) external {
        require(msg.sender == RECIPIENT, "Only recipient can close");
        require(isValidSignature(amount, signature), "Invalid signature");
        require(amount >= withdrawn);

        (bool sent,) = msg.sender.call{value: amount - withdrawn}("");
        require(sent, "Failed to send Eth");

        selfdestruct(payable(SENDER));
    }

    // close initiated by sender
    function startSenderClose() external {
        require(msg.sender == SENDER, "Cannot initiate");
        expiration = block.timestamp + closeDuration;
    }

    function claimTimeout() external {
        require(block.timestamp >= expiration);
        selfdestruct(payable(SENDER));
    }

    function deposit() public payable {
        require(msg.sender == SENDER, "Invalid sender");
    }

    function withdraw(uint amountAuthorized, bytes memory signature) external {
        require(msg.sender == RECIPIENT, "Invalid recipient");
        require(amountAuthorized >= withdrawn, "already withdrawn amount");

        require(isValidSignature(amountAuthorized, signature), "Invalid signature");

        uint amountToWithdraw = amountAuthorized - withdrawn;
        withdrawn = amountAuthorized;
        (bool sent,) = msg.sender.call{value: amountToWithdraw}("");
        require(sent, "tx failed");
    }

    function prefixed(bytes32 innerHash) public pure returns(bytes32){
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", innerHash));
    }

    function recoverSigner(bytes32 messageHash, bytes memory sig) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSig(sig);

        return ecrecover(messageHash, v, r, s);
    }

    function splitSig(bytes memory sig) public pure returns(bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Bad sig");
        assembly{
            r:= mload(add(sig, 32))
            s:= mload(add(sig, 64))
            v:= byte(0, mload(add(sig, 96)))
        }
    }

}