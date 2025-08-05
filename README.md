# Overview
![](https://github.com/phma/DaphneCipher.jl/blob/master/img/diagram.png?raw=true)
Daphne is a self-synchronizing byte stream cipher. Plaintext bytes are added to the accumulator, which runs the gantlope between the key (shown as 16 bytes, but it can be longer) and a shift register of as many previous ciphertext bytes, resulting in two keystream bytes, which encrypt the plaintext bytes using two different multiplications and an S-box. The same two multiplications and S-box are used in the gantlope to turn the accumulator in the keystream.

Decryption is similar; it uses the corresponding divisions and the inverse S-box. If the decrypter is out of sync with the encrypter, it will resynchronize when the shift register is fed enough bytes and the accumulators match.

# Julia
This is a Julia implementation. The reference implementations, in Rust and Haskell, are in the `daphne` repo.

In the project directory, run `julia --project` at the shell prompt, then in Julia run `using DaphneCipher`. You can then create a Daphne, key it, and encrypt some data.

# Testing
Type `]`. You get the `(DaphneCipher) pkg> ` prompt. Type `test`. You should get the same output as from the Rust and Haskell implementations, except for punctuation because of the syntax of ranges. To get out of `pkg` mode, hit backspace.
