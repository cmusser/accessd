#!/bin/sh

if [ "$#" -ne "2" ] ; then
    echo "usage: $0 <grant|revoke> <client>"
fi                

SERVER_INTF=igb0
ACTION=$1
CLIENT_ADDR=$2

SERVER_ADDR=$(ifconfig $SERVER_INTF | grep 'inet ' | awk '{print $2}')

if [ "$ACTION" = 'grant' ] ; then
    ALLOW_IN_CMD="/sbin/ipfw add allow tcp from ${CLIENT_ADDR} to ${SERVER_ADDR} dst-port 22"
    ALLOW_OUT_CMD="/sbin/ipfw add allow tcp from ${SERVER_ADDR} 22 to ${CLIENT_ADDR}"
    echo $ALLOW_IN_CMD
    echo $ALLOW_OUT_CMD
    eval "$ALLOW_IN_CMD"
    eval "$ALLOW_OUT_CMD"
    
elif [ "$ACTION" = 'revoke' ] ; then
    IN_RULE=$(/sbin/ipfw list | grep "from ${CLIENT_ADDR} to ${SERVER_ADDR} dst-port 22" | awk '{print $1}')
    OUT_RULE=$(/sbin/ipfw list | grep "from ${SERVER_ADDR} 22 to ${CLIENT_ADDR}"  | awk '{print $1}')
    REVOKE_IN_CMD="/sbin/ipfw delete ${IN_RULE}"
    REVOKE_OUT_CMD="/sbin/ipfw delete ${OUT_RULE}"
    echo $REVOKE_IN_CMD
    echo $REVOKE_OUT_CMD
    eval "$REVOKE_IN_CMD"
    eval "$REVOKE_OUT_CMD"
else
    echo "invalid action: $ACTION"
    exit 1
fi
