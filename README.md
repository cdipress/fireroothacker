# Linux Ransomware written in Go language

Go ransomware
=======================


## Abstract

This project provides a Linux client/server ransomware written in Go language. It is meant for educative purpose.
(_I am new to Go language and the code is poorly written, documented and organized_).

The client performs AES-128 (CBC) encryption of files in a directory and subdirectories. It uses a tor client to access the server
(also referred as Control Center). The client and its configuration file must be copied to the server and executed through command line,
so a terminal access to the target is required.

The server provides the decryption key (see below) when a bitcoin payment has been done to a specific address. 
The server must run as a [tor hidden service](https://www.torproject.org/docs/hidden-services.html.en) (a.k.a onion service )

## Disclaimer

Do not use on system where you don't have the permission of the owner

## Encryption
The AES key is generated using ECDH (Elliptic Curve Diffie-Hellman). It is inspired from this [article](http://securelist.com/analysis/publications/64608/a-new-generation-of-ransomware/).

The server has an EC key pair. The server's public key is visible from the client (read from a configuration file).
The client generates an EC key pair for each file, generates an AES key using (server pub key, client priv key) and only stores the client public key (in plain) in a header of the encrypted file.

For decryption, the client needs the server private key. In the current implementation, the server delivers directly the server private key for the client to 
compute the AES key for each file but it could only deliver the encrypted file's AES key


## Client Description

 * Includes a tor 0.2.5.10 client and is statically linked to it 
 * Can generate a web page asking for ransome. The current implementation expects a .htaccess file to be present and configures the .htaccess to display the web page (it is meant for web servers)
 * Its configuration includes :
    * The server public key (it is generated through the init command)
    * The onion url of the server 
    * The bitcoin address of the ransome for the web page
    * The amount of the ransome in bitcoin for the web page
 * Can poll frequently the server to get the decryption key 

## Server description

 * Current implementation is really simplistic. It starts a web server (to run behind a tor hidden service) and polls frequently [blockchain.info](https://blockchain.info)
 to check if the ransome has been paid
 * If ransome has been paid it delivers the private key to the client
 * Its configuration includes :
    * The server private key (it is generated through the init command)
    * The bitcoin address of the ransome to verify the payment 
    * The amount of the ransome in bitcoin to verify the payment

## Building

**!!Note that it has only been tested on debian wheezy!!**

### Dependencies

* Clone the current git repository in a staging directory
* Make sure go is installed properly and available in the path. It requires also mercurial/git to get dependencies
* Make, gcc and build tools must be installed (`sudo apt-get install build-essential`)

### Build

```
./makeRSW.sh
```

and have a coffee. Building of tor and its dependencies can take a few minutes.

### Binaries

Generated at the root of the staging directory:

* **rsw-client** : is the client executable to copy on the target
* **rsw-cc** : is the server

## Use

### Pre-requisites

* You need a specific bitcoin address for the payment with a 0btc balance on it
* For the server configure a [tor hidden service](https://www.torproject.org/docs/tor-hidden-service.html.en) and forward port to the ransomware server (7081 in our example).
You'll also need the hostname of the onion service
* Perform the initialization (configuration of client and server)

### Initialization

Initialization must be done on the server and not on the target host because it generates the server key pair 
```
./rsw-client -init
```
It will ask for :
* The onion server url
* The btc account address
* The btc amount

It generates file named `_rsw_cc_<timestamp>` which holds the client configuration and a file `_rsw_sc` which holds the server configuration

### Server

Copy the `rsw-cc` binary and `_rsw_sc` file into the same directory

#### Start server

```
./rsw-cc -port 7801 -poll 60 -debug
```
It will run the server on port 7801 in debug mode. Server will check the bitcoin account balance every 60 seconds.

### Client

Copy the `rsw-client` binary and `_rsw_cc_<timestamp>` file to the target host in the directory you want to encrypt


##### Encrypt files

```
./rsw-client -encrypt . -debug
```
Note that encryption ignores files and directories starting with `_rsw_`, or `.` and does not follow soft links.

##### Install the ransome web page

```
./rsw-client -installWP -debug
```
The client will generate a web page with a QR Code of the bitcoin address for the payment. The name of the web page is `_rsww_.html` 

It will also try to reconfigure a .htaccess file to define the `_rsww_.html` as the default home page. 

It is probably not what you want, so you might need to customize the source code (see _InstallWP_ function) 

##### Query the server for decryption key

```
nohup ./rsw-client -waitForCC -debug -poll 600 &
```

The client will start the tor socks proxy on port 9050 (not configurable) and query the server for the decryption key every 600 seconds

If the tor client startup fails the client does not exit (to be improved) 

If the payment is made, the process will automatically decrypt the files and exit. 

#### Do all the above in 1 command
```
nohup ./rsw-client -encrypt . -installWP -waitForCC -poll 600 -debug &
```

## Possible improvements

* Replace the tor client with an online tor proxy service (tor2webproject ?) for portability
* Use compressed public address to win space on the client
* Have the client and server support decryption of each file individually  
* ...

