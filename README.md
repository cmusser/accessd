# accessd

Host access system/Rust testbed

## Introduction

`accessd` allows clients to send a request to temporarily grant access to a system. The server manages the access by running a script that, in most cases, reconfigures the firewall. It then waits for a period of time, then runs the script again to unconfigure the firewall exception created earlier. Delegating the access details to a script enables multi-platform support and also site-specific policies about the nature of the granted access. A script compatible with the BSD `ipfw(2)` command that grants SSH access is included, but scripts for other systems (Linux iptables and `pf`) should be easy to create. For security, the request packets use NaCl's authenticated encryption scheme. This means that requests are only accepted from entities for whom the server has a public key and the actual contents of the request are shrouded from view. Nonces are used so that captured packets may not be resent later and succeed in opening the firewall

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

## Usage

The system has four components

- `accessd`: the server, which manages access
- a firewall configuration script. One compatible with the FreeBSD `ipfw(2)` system is provided. 
- `access`: the client, which requests access
- `access-keygen`: a program to generate public private keypairs

To use:

1. run `access-keygen` twice (for the server and the client) to generate keypairs for the two peers.
  ```
  cargo run --bin access-keygen -- access
  cargo run --bin access-keygen -- accessd
  ```
  These commands create keypair files named `access_keypair.yaml` and `accessd_keypair.yaml`.

2. Create key data files for the peers. For the client, copy the `access_keypair.yaml` file to `access_keydata.yaml`, change the `public` field name to `peer_public` and replace the data for that field by pasting in the `public` value from `accessd_keypair.yaml`. For the server, repeat this procedure with the `accessd_keypair.yaml`, copying it to `access_keydata.yaml`, renaming `public` to `peer_public` and pasting in the public value from `access_keypair.yaml`. *Note: yes this is clunky. There should be a utility program to facilitate the "key exchange" process.*

3. On the server machine, run `accessd`:
  ```
  sudo sh -c 'cargo run --bin accessd -d 900 $(pwd)/ipfw-ssh.sh > accessd.out &'
  ```
  This will grant access for 15 minutes. The default is 5 seconds, which was good for initial testing, but should probably be changed now. Note that the firewall management script provided is for the `ipfw(2)` firewall system used by {Free,DragonFly}, and opens up access to port 22 (SSH). You'll have to write your own script for other firewall systems (iptables, `pf(4)`, NPF, etc). The script is invoked with two arguments. The first is the word `grant` or `revoke` and the second is the IP address to which the request is to apply.
  
4. On the client, you can request access to the server with a command like this:
  ```
  cargo run --bin access -- 1.2.3.4
  ```
  By default, this will grant access to the IP address used as the source address for the request packet, which will be chosen by the OS. If you want to specify the address, use the `-a` flag to do so. If you don't want to specify the address, but want to make sure that the system chooses an IPv4 address, use the `-4` flag. Dual-stack support in `accessd` is not quite right yet, which is why the `-4` flag exists in the client for now.
  
The commands don't need to be run using Cargo, of course. Just copy them out of the source directory's `target/{debug,release}` directory to a convenient place, like `/usr/local/bin`.
