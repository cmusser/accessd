# accessd

Secure and temporary access to hosts

## Introduction

`accessd` allows clients to send a request for temporary access to a system. The server manages the access by running a script to reconfigure the firewall. It then waits for a period of time, then runs the script again to unconfigure the firewall exception created earlier. The details of how to grant access are delegated to the script, which means many platform can be supported. A script that grants SSH access through via BSD `ipfw(2)` is included. Scripts can be easily written for other systems as well. For security, NaCl's authenticated encryption scheme is used to provide confidentiality, integrity and authentication. Only requests from entities for whom the server has a public key are accepted. the actual contents of the request are shrouded from view. Replay protection is provided by a ever increasing sequence IDs contained in the packet payload, which the server will verify is always greater than one seen before.

## Programs

The system has four components:

1. `accessd`: the server, which manages access
2. a firewall configuration script.
3. `access`: the client, which requests access
4. `access-keygen`: a program to generate public private keypairs

## Usage

1. On the server, un `access-keygen` to generate a keypair. The output file looks like:
  ```
  secret: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
public: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
  ```

2. Put the secret key in `/etc/accessd_keydata.yaml`. The file should be owned by root and contain the following at this point:

  ```
  secret: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
  ```

3. Change the permissions of the file:
```
chmod 600 /etc/accessd_keydata.yaml
```

4. Give the public key to trusted users who you want to be able to access your system.

5. Users should run `access-keygen`. Take the secret key from the generated file and create a file in `~/.access/keydata.yaml` that contains the secret key and the public key from the server. It should look like this:
```
secret: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
peer_public: CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC
```

6. Change the permissions of the file:
```
chmod 600 ~/.access/keydata.yaml
```

Note that the replay protection relies on an ever-increasing request ID that the server associates with each public key. User who have multiple client hosts should generate a separate key for each one. If the client keys are shared, and you make a series of requests from client host 1, and then start making them from client host 2, the replay protection will reject requests until the request IDs on host 2 "catch up". Avoid this situation by creating a separate key for each host.

7. On the server, add the public keys of users to the `/etc/accessd_keydata.yaml` file. A file with two users will look like this:
```
secret: BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
peer_public_keys:
  bob: DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD
  joe: FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
```

8. Start the server:
```
/usr/local/sbin/accessd  /usr/local/sbin//ipfw-ssh.sh
```

9. On a client:
  ```
  access secured-host.com 
  ```
  By default, this will grant access to the source address of the request packet. If you want to specify the address, use the `-a` flag to do so. If you don't want to specify the address, but want to make sure that the system chooses an IPv4 address, use the `-4` flag.

## Motivation

This program was inspired by the `knockd` and `sshlockout` programs, which aim to increase security by limiting access to the administrative interfacves of hosts.

A major goal was to utilize the Tokio framework, which uses the notion of "futures" (known as "promises" in other languages) to create a server that handled requests asynchronously. It's entirely reasonable to write something like this in C, but lots of low-level details have to be managed (the event loop, a datastore for the shared state, command line handling, etc.).

As a whirlwind tour of Rust, `accessd` covered a fair amount of ground. Specifically:

- Tokio streams: allows handling an endless sequence of events, in this case the exchange of UDP packet between client and server.
- Tokio process: allows operating system processes to be spawned asynchronously and their output and exit status captured.
- Combinators, which allow a series of events to be chained together elegantly while keeping the system entirely asynchronous. The "process packet, open firewall, wait a while, close firewall" sequence is made possible via combinators.
- Serde, which is used to handle the persistent key and state data for the client and server programs, using YAML. It also is used to encode and decode the request messages, using CBOR. Early versions used the Nom parser, which is a novel and interesting library.
- The Clap command line argument processor: provides a convenient command-line utility.
- The sodiumoxide Rust bindings to libsodium (the widely used implementation of the NaCl security suite).
- Various bread-and-butter Rust constructs: structs,  traits, enums, match statements, if-let. 
- Shared mutable state, using a `HashMap` and the `Rc`/`RefCell` wrapping technique to make it available safely.
