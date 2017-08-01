# accessd

Host access system/Rust testbed

## Introduction

`accessd` allows clients to send a request to temporarily grant access to a system. The server manages the access by running a script that, in most cases, reconfigures the firewall. It then waits for a period of time, then runs the script again to unconfigure the firewall exception created earlier. Delegating the access details to a script enables multi-platform support. A script that works with the BSD `ipfw(2)` command is included, but scripts for other systems (Linux iptables and `pf`) should be easy to create. For security, the request packets use NaCl's authenticated encryption scheme. This means that requests are only accepted from entities for whom the server has a public key and the actual contents of the request are shrouded from view. Nonces are used so that captured packets may not be resent later and succeed in opening the firewall

## Motivation

The main goal was to utilize the Tokio framework, which uses the notion of "futures" (known as "promises" in other languages) to create a server that handled requests asynchronously. It's entirely reasonable to write something like this in C, but lots of low-level details have to be managed (the event loop, a datastore for the shared state, command line handling, etc.).

As a whirlwind tour of Rust, `accessd` covered a fair amount of ground. Specifically:

- Tokio streams: allows handling an endless sequence of events, in this case a stream of UDP.
- Tokio process: allows operating system processes to be spawned asynchronously and their output and exit status captured.
- The Nom parser: used here to decode the incoming access request messages
- The Clap command line argument processor: provides a convenient command-line utility.
- THe sodiumoxide Rust bindings to libsodium (the widely used implementation of the NaCl security suite).
- Various bread-and-butter Rust constructs: structs (with both `impl` and `impl` of traits), enums, match statements, if-let. 
- Shared mutable state, using a `HashMap` and the `Rc`/`RefCell` wrapping technique to make it available safely.
