# Interceptor

Use this Python script to spot the attacker in your network.  
The attacker who uses the wide spread tools: Responder, Inveigh and the alike.

## Attack

There is a well-known technique which abuses the Microsoft Windows' single-sign-on functionality in order to
capture the user's Net-NTLMv1/v2 (sometimes named NTLMv1/v2) hashes.
Those hashes can further be used to attack the other systems
on the network.

There are hacking tools that use this technique, the most popular one is the Responder. Windows based analog is the Inveigh.
Both these tools (in fact, all tools that target this specific Windows' behaviour) rely on sniffing the network traffic, looking
for the broadcast name resolution requests and sending poisoned replies, eventually forcing the Windows client to connect to the
attacker's system and to expose the Net-NTLM hashes.

The ones who seek more details about this attack can find lots of relevant information on the Net.

## Concept

It is not something new that Responder can be detected by sending the dummy name resolution requests (NBNS, or LLMNR)
and rising an alert upon the received replies (from the Responder).

The disadvantage of the existing solutions is that they require the sending system to be placed in the network segment, which
you wish to monitor. This happens because those solutions send requests to the real multicast (224.0.0.252 in case of LLMNR)
or broadcast (in case of NBNS) addresses. It turns out that the Responder (nor Inveigh) does not check if the name resolution request
was sent to the actual broadcast address. That is to say, Responder sends poisoned replies even if it receives request that was sent
to the unicast address (which is not how NBNS, LLMNR name resolution works).

This creates a good opportunity to detect Responder. One can send dummy name resolution requests to every host in the multiple
higher risk networks from the single system and alert about the poisoned replies.
This is exactly what the Interceptor does.

## How it works

Interceptor gets the list of the target subnets from the configuration file, sets up the sniffer thread,
and starts sending artificial NBNS and LLMNR name resolution requests. If the sniffer receives a reply, it logs a message
in the log file (which you can monitor using your SIEM system) and (optionally) posts to the Slack channel.
