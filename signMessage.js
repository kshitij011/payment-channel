import { secp256k1 } from "ethereum-cryptography/secp256k1.js";
import { keccak256 } from "ethereum-cryptography/keccak.js";
import { hexToBytes, bytesToHex } from "ethereum-cryptography/utils.js";

async function signPayment({ privateKeyHex, channelAddress, amount }) {
    const priv = hexToBytes(
        privateKeyHex.startsWith("0x") ? privateKeyHex.slice(2) : privateKeyHex
    );
    if (priv.length !== 32) throw new Error("Private key must be 32 bytes");

    // --- abi.encodePacked(address(this), amount) ---
    function packAddressUint256(addressHex, amountBigInt) {
        const addr = hexToBytes(addressHex.slice(2));
        if (addr.length !== 20) throw new Error("address must be 20 bytes");

        const amt = new Uint8Array(32);
        let x = amountBigInt;
        for (let i = 31; i >= 0; i--) {
            amt[i] = Number(x & 0xffn);
            x >>= 8n;
        }
        const out = new Uint8Array(addr.length + amt.length);
        out.set(addr, 0);
        out.set(amt, addr.length);
        return out;
    }

    function channelInnerHash(channelAddress, amount) {
        return keccak256(packAddressUint256(channelAddress, BigInt(amount)));
    }

    function toEthSignedMessageHash(innerHashBytes) {
        const prefix = new TextEncoder().encode(
            "\x19Ethereum Signed Message:\n32" // literal characters: 3, 2
        );
        const out = new Uint8Array(prefix.length + innerHashBytes.length);
        out.set(prefix, 0);
        out.set(innerHashBytes, prefix.length);
        return keccak256(out);
    }

    const inner = channelInnerHash(channelAddress, amount);
    const ethHash = toEthSignedMessageHash(inner);

    // 👉 new API: returns signature (64 bytes) + recovery (0/1)
    const sig = secp256k1.sign(ethHash, priv);
    const signature = sig.toCompactRawBytes(); // 64 bytes r||s
    const recovery = sig.recovery; // 0 or 1

    const r = "0x" + bytesToHex(signature.slice(0, 32));
    const s = "0x" + bytesToHex(signature.slice(32, 64));
    const v = 27 + recovery; // 27 or 28

    const sig65 = new Uint8Array(65);
    sig65.set(signature, 0);
    sig65[64] = v;

    return {
        messageHash: "0x" + bytesToHex(ethHash),
        signatureBytes: "0x" + bytesToHex(sig65),
        r,
        s,
        v,
    };
}

// --- Example usage ---
const res = await signPayment({
    privateKeyHex: process.env.PRIVATE_KEY,
    channelAddress: "0xC573C58EfFCdE6f66034566Be7f00153082cE2DB",
    amount: 150000000000000000n,
});

console.log(res);
