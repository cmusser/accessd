# accessd

Host access system/Rust testbed

## Introduction

`accessd` allows clients to send a request to temporarily grant access to a system. The server manages the access by running a script that, in most cases, reconfigures the firewall. It then waits for a period of time, then runs the script again to unconfigure the firewall exception created earlier. Delegating the access details to a script enables multi-platform support. A script that works with the BSD `ipfw(2)` command is included, but scripts for other systems (Linux iptables and `pf`) should be easy to create. Note that there is *no cryptographic protection* on the request packets, meaning that anyone who can send a valid request message will be granted access. Do not depend on `accessd` for security in its current form. If you ignore this warning, make sure you limit your exposure by only opening access to services that are secured in some other way, like SSH. The point of this program was to explore the Rust language and make a working program, not save the world or launch a zillion dollar security startup.

## Motivation

The main goal was to utilize the Tokio framework, which uses the notion of "futures" (known as "promises" in other languages) to create a server that handled requests asynchronously. It's entirely reasonable to write something like this in C, but lots of low-level details have to be managed (the event loop, a datastore for the shared state, command line handling, etc.).

The Rust community has provide "crates" for ancillary (but important) functionality. The Tokio framework is designed from the ground up to be asynchronous. Though it's daunting to get started with, it has powerful features. For example, futures can be chained together with functions called "combinators". This has an interesting effect: many outstanding requests can be happening concurrently (and completing asynchronously), yet the steps that make up each request appear "synchronous" in the sense that they are grouped together in the code and start only when the previous step has completed successfully.

Sounds amazing, and most of it is, but coming up to speed takes a major effort. A major stumbling block is the inherent difficulty in getting a Rust program to compil. The approach is to essentially force you to write a memory safe program upfront, rather than get something working and then fixing the memory leaks, use-after-frees, unsafe shared accesses and other bugs later (or never). This is a slow, frustrating experience, exacerbated by compiler error messages that often confuse. Also, despite what appears to be a very diligent effort at writing documentation, parts of the Rust language and libraries (Tokio in particular) are hard to understand.

All kvetching aside, the `accessd` system works and as a whirlwind tour of Rust, it covered a lot of ground. Specifically:

- Tokio streams: allows handling an endless sequence of events, in this case a stream of UDP.
- Tokio process: allows operating system processes to be spawned asynchronously and their output and exit status captured.
- The Nom parser: used here to decode the incoming access request messages
- The Clap command line argument processor: provides a convenient command-line utility.
- Various bread-and-butter Rust constructs: structs (with both `impl` and `impl` of traits), enums, match statements, if-let. 
- Shared mutable state, using a `HashMap` and the `Rc`/`RefCell` wrapping technique to make it available safely.
