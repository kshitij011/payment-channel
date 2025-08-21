1. Add your private key to .env

2. Enter amount you want to send receiver

3. Enter contract address where receiver obtains funds from

4. Run the signMessage file, it will return a signature

5. Deploy the contract on sepolia passing funds, receiver's address and duration

6. Switch to receiver's account and call close() function, passing the amount and signature

# Note: Running on hardhat may return incorrect balances as the hardhat 3 is in beta development.
