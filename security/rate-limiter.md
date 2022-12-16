
## Synopsis

This document specifies the data structures and state machine handling logic for a rate limiter module placed between the fungible token transfer bridge module (ICS20) and IBC core. This module enables chains to limit the amount of tokens that are sent an received within a period of time.

## Overview and Basic Concepts

### Motivation

TODO

### Definitions 

`FlowPath` is a tuple of a denom and a channel.

`Flow` represents the transfer of value for a denom through an IBC channel during a time window.
Tokens can flow both in and out. When a chain receives tokens, we say that they flow in. When a chain sends tokens, we say that they flow out.

A `Quota` is the percentage of the denom's total value that can be transferred through the channel in a given period of time (duration).

A `RateLimiter` is the main structure tracked for each channel/denom pair, i.e., for each `FlowPath`. It is associated with a `Quota` and a `Flow`. Its quota represents the rate limiter configuration, and the flow its current state.

`FungibleTokenPacketData` is as defined in ICS 20.

`Identifier`, `get`, `set`, `delete` and module-system related primitives are as defined in ICS 24.

## System Model and Properties

### Assumptions

The module has access to a `bank` module. The specification assumes that this module permits the rate limiter module to query:
(i) the escrowed amount for a given denom and channel pair, and (ii) the total available supply of tokens for a given denom in the chain.

TODO: more assumptions

### Desired properties

TODO

## Technical Specification

### General Design 

TODO: How it works in a few words

A period only starts when the Flow is updated via receiving or sending a packet, and not right after the period ends. This means that if no calls happen after a period expires, the next period will begin at the time of the next call and be valid for the specified duration for the quota. This is a design decision to avoid the period calculations and thus reduce gas consumption.

The channel value is reset when the duration expires or if it has not been set. This is important: once set and while the duration does not expire, the channel value does not change.

### Data structures

A `FlowPath` is defined as:

```typescript
interface FlowPath {
  denom: string
  channel: Identifier
}
```

A `Flow` is defined as:

```typescript
interface Flow {
  inflow: uint
  outflow: uint
  periodEnd: uint
}
```
Tokens can flow in two directions:

```typescript
enum FlowDirection {
  IN,
  OUT
}
```
A `Quota` is defined as:

```typescript
interface Quota {
  name: string
  maxPercentageSend: uint
  maxPercentageRecv: uint
  duration: uint
  channelValue: uint
}
```
Percentages can be different for send and receive. The name of the quota is expected to be a human-readable representation of the duration (i.e.: "weekly", "daily", "every-six-months", ...).

A `RateLimiter` is a tuple of a `Quota` and `Flow`.

```typescript
interface RateLimiter {
  quota: Quota
  flow: Flow
}
```
### Store paths

The rate limiter path is a private path that stores rate limiters.

```typescript
function rateLimiterPath(channel: Identifier, denom: string): Path {
    return "ratelimiter/{id}/{denom}"
}
```

### Key helper functions

The `computeChannelValue` computes the channel value of a given denom depending of whether the chain is the source of the denom or not. In this specification we are proposing one possible way of computing the channel value, but one could think of alternatives. This has to be thought carefully: it determines how many tokens can be sent or received for a period of time.

Channel value may be computed when sending or receiving tokens. Depending on whether the source chain is the denom source or not, we have four cases:

1) Send a native token: the sending chain is the denom source.
2) Receive a native token: the receiving chain is the denom source.
3) Send a non-native token: the sending chain is not the denom source.
4) Receive a non-native token: the receiving chain is not the denom source.

This specification proposes the following:
- For (1), channel value = the available supply of denom in the sender chain. This may be a bit risky, as the total supply may be very large.
- For (2), channel value = escrow value (per channel and denom) in the receiver chain. One cannot receive more than what is in the escrow anyway, and this way we prevent attackers from emptying the escrow accounts completely.
- For (3), channel value = the available supply (minted) of denom in the sender chain. Not risky, as this means only the tokens received through THIS channel due to prefixing of channel ids to denoms.
- For (4), channel value = the available supply of denom in the sender chain.

Note that the `bank` module used by the function is unspecified.

```typescript
function computeChannelValue(
    channelId: Identifier,
    source: bool,
    direction: FlowDirection,
    denom: string): int {
    if (source && direction === IN) {
        escrowAccount = channelEscrowAddresses[channelId]
        return bank.GetEscrowDenom(escrowAccount, denom)
    } else {
        return bank.GetAvailableSupply(denom)
    }
}
```

The `checkAndUpdateRateLimits` function checks whether a send or receive should be processed or not depending on the rate limiter associated to the channel and denom. If it is accepted, then the rate limiter is updated to account for the newly sent/received tokens.

The function introduces two concepts: flow balance and quota capacity. Flow balance is how much absolute value for the denom has moved through the channel during the current period. Quota capacity is how much value the quota allows to transfer in both directions in a given period of time.

Note that channel value is reset when the duration expires or if it has not been set. This is important: once set and while the duration does not expire, the channel value does not change.

```typescript
function checkAndUpdateRateLimits(
    channelId: Identifier,
    source: bool,
    denom: string,
    amount: int,
    direction: FlowDirection): error {
    // retrieve RateLimiter, quota and flow
    rateLimiter = privateStore.get(rateLimiterPath(channelId, denom))
    quota = rateLimiter.quota
    flow = rateLimiter.flow
    // compute balances
    balanceIn = flow.inflow - flow.outflow
    balanceOut = flow.outflow - flow.inflow

    now = currentTimestamp()
    if (now > flow.periodEnd) {
        // period has expired, reset flow
        flow.inflow = 0
        flow.outflow = 0
        flow.periodEnd = now + quota.duration
        quota.channelValue = computeChannelValue(channelId, source, direction, data.denom)
    }

    // compute capacity
    capacityIn = quota.channelValue * quota.maxPercentageRecv/100
    capacityOut = quota.channelValue * quota.maxPercentageSend/100

    // if tokens are received
    if (direction === IN) {
        if ( balanceIn + amount < capacityIn ) {
            // we haven't reached the limit
            // update inflow
            flow.inflow = flow.inflow + amount
        } else {
            // limit reached
            return RateLimitExceededError
        }
    // if tokens are sent
    } else {
        if ( balanceOut + amount < capacityOut ) {
            // we haven't reached the limit
            // update inflow
            flow.outflow = flow.outflow + amount
        } else {
            // limit reached
            return RateLimitExceededError
        }
    }

    //update rate limiter
    rateLimiter.quota = quota
    rateLimiter.flow = flow
    privateStore.set(rateLimiterPath(channelId, denom), rateLimiter)
    
    return nil
}
```
The function `undoSend` is called when an send of tokens went wrong. The function simply rolls back the outflow by substracting the amount sent.

```typescript
function undoSend(packet: Packet) {
    FungibleTokenPacketData data = packet.data
    prefix = "{packet.sourcePort}/{packet.sourceChannel}/"
    // we are the source if the denomination is not prefixed
    source = data.denom.slice(0, len(prefix)) !== prefix
    if source {
        // the denom source chain; remove the denom prefix
        denom = data.denom.slice(len(prefix))
    } else {
        // not the denom source chain
        denom = data.denom
    }
    rateLimiter = privateStore.get(rateLimiterPath(packet.sourceChannel, denom))
    rateLimiter.flow.outflow = rateLimiter.flow.outflow - data.amount
    privateStore.set(rateLimiterPath(packet.sourceChannel, denom), rateLimiter)
}
```

### Sub-protocols

`SendPacket` should be called after `sendFungibleTokens` of the fungible token transfer bridge module (ICS20) and before the send packet defined in ICS4.

```typescript
function SendPacket(packet: Packet): error {
    FungibleTokenPacketData data = packet.data
    prefix = "{packet.sourcePort}/{packet.sourceChannel}/"
    source = data.denom.slice(0, len(prefix)) === prefix
    // retrieve RateLimiter
    rateLimiter = privateStore.get(rateLimiterPath(packet.sourceChannel, data.denom))
    // if the rate limiter exists for this flow path, then check quota
    if (rateLimiter !== nil) {
        err = checkAndUpdateRateLimits(packet.destChannel, source, data.denom, data.amount, IN)
        if (err !== nil)
            return err
    }
    return nil
}
```

`onRecvPacket` is called by the routing module when a packet addressed to this module has been received, before `onRecvPacket` at the fungible token transfer bridge module.

```typescript
function onRecvPacket(packet: Packet): error {
    FungibleTokenPacketData data = packet.data
    prefix = "{packet.sourcePort}/{packet.sourceChannel}/"
    source = data.denom.slice(0, len(prefix)) === prefix
    if source {
        // the denom source chain; remove the denom prefix
        denom = data.denom.slice(len(prefix))
    } else {
        // not the denom source chain
        denom = data.denom
    }
    // retrieve RateLimiter
    rateLimiter = privateStore.get(rateLimiterPath(packet.destChannel, denom))
    // if the rate limiter exists for this flow path, then check quota
    if (rateLimiter !== nil) {
        err = checkAndUpdateRateLimits(packet.destChannel, source, denom, data.amount, IN)
        if (err !== nil)
            return err
    }
    return nil
}
```

The function `onAcknowledgePacket` calls `undoSend` if the tokens were not accepted by the receiver chain.

```typescript
function onAcknowledgePacket(
    packet: Packet,
    acknowledgement: bytes) {
    // if the transfer failed, undo send
    if (!ack.success)
        undoSend(packet)
}
```

The function `onTimeoutPacket` always calls `undoSend`

```typescript
function onTimeoutPacket(packet: Packet) {
    // the packet timed-out, so refund the tokens
    undoSend(packet)
}
```