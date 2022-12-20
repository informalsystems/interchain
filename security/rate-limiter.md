# IBC Rate Limiter

- [IBC Rate Limiter](#ibc-rate-limiter)
  - [Synopsis](#synopsis)
  - [Overview and Basic Concepts](#overview-and-basic-concepts)
    - [Motivation](#motivation)
    - [Definitions](#definitions)
  - [System Model and Properties](#system-model-and-properties)
    - [Assumptions](#assumptions)
    - [Desired Properties](#desired-properties)
  - [Technical Specification](#technical-specification)
    - [General Design](#general-design)
    - [Data Structures](#data-structures)
    - [Store Paths](#store-paths)
    - [Key Helper Functions](#key-helper-functions)
      - [Computing the Channel Value](#computing-the-channel-value)
        - [Proposal](#proposal)
      - [Checking and Updating Rate Limits](#checking-and-updating-rate-limits)
      - [Undoing a Send](#undoing-a-send)
    - [Sub-protocols](#sub-protocols)
  - [Further Reading \& References](#further-reading--references)

## Synopsis

This document specifies the data structures and state machine handling logic for a rate limiter module. The modules is designed to intermediate between the fungible token transfer bridge module (ICS20) and IBC core. The aim of this module is to enable chains to limit the amount of tokens that are sent and received within a period of time.

The present specification is modeled after the [Osmosis IBC Rate Limit][osmosis-ibc-rate-limit] module.

## Overview and Basic Concepts

### Motivation

The IBC rate limiter can temper the impact of certain security problems. Specifically, it can prevent anomalous transfers of ICS20 funds across IBC networks.

The logic behind a rate limiter is that assets are flowing through an IBC channel at a certain rate. This is the common-case situation. In situations of exploits or bugs, however, assets typically flow at a higher (anomalous) rate; in this case, a rate limiter can prevent complete draining of a bridged asset. It acts as a liveness throttling mechanism, in other words. The limier can also raise awareness that an exploit might be ongoing in such an event. The [BNB hack][bnb-bridge-hack] is an example of a problem that could have been alleviated by a rate limiter.

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

The IBC rate limiter module has access to a `bank` module similar to the one implemented in the [SDK](https://github.com/cosmos/cosmos-sdk/blob/main/x/bank/README.md). The specification assumes that this module permits the rate limiter module to query:
(i) the escrowed amount for a given denom and channel pair via the `bank.GetEscrowDenom` function, and (ii) the total available supply of tokens of a given denom via the `bank.GetAvailableSupply` function.

TODO: more assumptions

### Desired Properties

TODO

## Technical Specification

### General Design

TODO: How it works in a few words

Text from the doc that could be used here:

A period only starts when the Flow is updated via receiving or sending a packet, and not right after the period ends. This means that if no calls happen after a period expires, the next period will begin at the time of the next call and be valid for the specified duration for the quota. This is a design decision to avoid the period calculations and thus reduce gas consumption.

### Data Structures

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

A `RateLimiter` is a tuple of a `Quota` and a `Flow`.

```typescript
interface RateLimiter {
  quota: Quota
  flow: Flow
}
```

### Store Paths

The rate limiter path is a private path that stores rate limiters.

```typescript
function rateLimiterPath(channel: Identifier, denom: string): Path {
    return "ratelimiter/{channel}/{denom}"
}
```

### Key Helper Functions

#### Computing the Channel Value

The `computeChannelValue` function computes the channel value of a given denom depending of whether the chain is the source of the denom or not. In this specification we are proposing one possible way of computing the channel value, but one could think of alternatives. Setting the channel value has to be done carefully: it determines how many tokens can be sent or received for a period of time.

Channel value may be computed when sending or receiving tokens. Depending on whether the source chain is the denom source or not, we have four cases:

1) Send a native token: the sending chain is the denom source.
2) Receive a native token: the receiving chain is the denom source.
3) Send a non-native token: the sending chain is not the denom source.
4) Receive a non-native token: the receiving chain is not the denom source.

##### Proposal

This specification proposes the following:

- For (1), channel value = the available supply of denom in the sender chain. This may be risky, as the total supply may be very large.
- For (2), channel value = escrow value (per channel and denom) in the receiver chain. One cannot receive more than what is in the escrow anyway, and this way we prevent attackers from emptying the escrow accounts completely.
- For (3), channel value = the available supply (minted) of denom in the sender chain. Not risky, as this means only the tokens received through THIS channel due to prefixing of channel ids to denoms.
- For (4), channel value = the available supply of denom in the sender chain.

```typescript
function computeChannelValue(
    channelId: Identifier,
    source: bool,
    direction: FlowDirection,
    denom: string): int {
    if (source && direction === IN) {
        // Handle case (2)
        escrowAccount = channelEscrowAddresses[channelId]
        return bank.GetEscrowDenom(escrowAccount, denom)
    } else {
        // Cases (1), (3), and (4)
        return bank.GetAvailableSupply(denom)
    }
}
```

#### Checking and Updating Rate Limits

The `checkAndUpdateRateLimits` function checks whether a send or receive should be processed or not (i.e., limited) depending on the rate limiter associated to the channel and denom. If it is accepted, then the rate limiter is updated to account for the newly sent/received tokens.

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

#### Undoing a Send

The function `undoSend` is called when a send of tokens went wrong. (See `onAcknowledgePacket`  or `onTimeoutPacket` [sub-protocols](#sub-protocols) below for usage of `undoSend`.) This function simply rolls back the outflow by substracting the amount sent.

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

The `SendPacket` function should be called after `sendFungibleTokens` of the fungible token transfer bridge module (ICS20) and before the send packet defined in ICS4. This method calls into `checkAndUpdateRateLimits` to potentially throttle the sending of this packet if the quota has been exceeded.

```typescript
function SendPacket(packet: Packet): error {
    FungibleTokenPacketData data = packet.data
    prefix = "{packet.sourcePort}/{packet.sourceChannel}/"
    source = data.denom.slice(0, len(prefix)) === prefix
    // retrieve RateLimiter
    rateLimiter = privateStore.get(rateLimiterPath(packet.sourceChannel, data.denom))
    // if the rate limiter exists for this flow path, then check quota
    if (rateLimiter !== nil) {
        err = checkAndUpdateRateLimits(packet.destChannel, source, data.denom, data.amount, OUT)
        if (err !== nil)
            return err
    }
    return nil
}
```

Function `onRecvPacket` is called by the routing module when a packet addressed to this module has been received, before `onRecvPacket` at the fungible token transfer bridge module.

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

## Further Reading & References

- [Osmosis IBC rate limit module][osmosis-ibc-rate-limit]
- Circuit breaker SDK [feature](https://github.com/cosmos/cosmos-sdk/issues/14226)

<!-- Links & References -->

[osmosis-ibc-rate-limit]: https://github.com/osmosis-labs/osmosis/tree/v13.0.0/x/ibc-rate-limit
[bnb-bridge-hack]: https://rekt.news/bnb-bridge-rekt/
