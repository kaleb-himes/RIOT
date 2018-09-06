# dtls_wolfssl example

This example shows how to use DTLS with wolfSSL

## SOCK vs. Socket

This example is configured to use socks instead of sockets (over GNRC).
It's possible to use sockets, which give a more similar approach to the
UNIX version of wolfSSL.

## Fast configuration (Between RIOT instances):

Preparing the logical interfaces:

    ./../../dist/tools/tapsetup/tapsetup --create 2

For the server instance:

    make all; PORT=tap1 make term
    dtlss start
    ifconfig

Do not forget to copy the IPv6 addresses!

For the client:

    PORT=tap0 make term
    dtlsc <IPv6's server address[%netif]> "DATA to send under encrypted channel!"

# Testings
## Boards

Boards that do not support the `../gnrc_networking` example are included
in the `BOARD_INSUFFICIENT_MEMORY`, plus the board `cc2650stk`.

