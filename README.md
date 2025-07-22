# Overview
Daphne is a self-synchronizing byte stream cipher.

# Julia
This is a Julia implementation. The reference implementations, in Rust and Haskell, are in the `daphne` repo.

In the project directory, run `julia --project` at the shell prompt, then in Julia run `using DaphneCipher`. You can then create a Daphne, key it, and encrypt some data.

# Testing
Type `]`. You get the `(DaphneCipher) pkg> ` prompt. Type `test`. You should get the same output as from the Rust and Haskell implementations, except for punctuation because of the syntax of ranges. To get out of `pkg` mode, hit backspace.
