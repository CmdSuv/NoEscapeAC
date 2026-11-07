# NoEscapeAC Server-Authoritative Anti-Cheat Integration Guide

**Project:** NoEscapeAC — Unified Ring-3 Anti-Cheat Architecture  
**Architects:** Omar Yiğitcan Mengü (`@CmdSuv`) & OnlyCosmos (`@OnlyCosmos`)  
**Target Environments:** Linux & Windows Dedicated Game Servers  
**Header:** `include/noescape/server/server_integration.hpp`  
**Source:** `src/server/server_integration.cpp`  

---

## 1. The Server-Authoritative Defense Model

Ring-3 client-side anti-cheat cannot observe kernel memory modifications, hypervisors, or physical DMA PCIe leech cards. Attempting to detect unobservable client hardware using user-mode heuristics creates false positives and endless cat-and-mouse races.

**The Ultimate Solution:**
> *Never send data to a client that their player cannot legitimately observe.*

If the server never replicates enemy coordinates to an observer's machine while they are behind a solid wall, **no client-side cheat — whether Ring-3, kernel driver, hypervisor, or external DMA card — can display an ESP wallhack or target an aimbot.**

NoEscapeAC provides `ServerEspFilter`, an optimized, high-throughput C++20 server component implementing 3D AABB raycast occlusion culling, acoustic cue spatialization, and authoritative movement validation.

---

## 2. 3D AABB Raycast Slab Method Architecture

### 2.1 The Ray-AABB Intersection Algorithm
For an observer at position $\vec{P}$ and target at position $\vec{T}$, the sightline ray is:
$$\vec{R}(t) = \vec{P} + t (\vec{T} - \vec{P}), \quad t \in [0, 1]$$

An axis-aligned bounding box (AABB) is defined by $[\vec{B}_{min}, \vec{B}_{max}]$. For each dimension $i \in \{x, y, z\}$:
$$t_{1, i} = \frac{B_{min, i} - P_i}{T_i - P_i}, \quad t_{2, i} = \frac{B_{max, i} - P_i}{T_i - P_i}$$
$$t_{near} = \max(\min(t_{1, x}, t_{2, x}), \min(t_{1, y}, t_{2, y}), \min(t_{1, z}, t_{2, z}))$$
$$t_{far} = \min(\max(t_{1, x}, t_{2, x}), \max(t_{1, y}, t_{2, y}), \max(t_{1, z}, t_{2, z}))$$

An intersection occurs if:
$$t_{near} \le t_{far} \quad \text{and} \quad t_{far} \ge 0 \quad \text{and} \quad t_{near} \le 1$$

If any occluder box satisfies this condition, the line of sight is **fully occluded**.

---

## 3. Replication Evaluation & Acoustic Cue Spatialization

### 3.1 Decision Flowchart

```
                 [ Target Entity in Game World ]
                               │
                               ▼
               Distance > MaxReplicationDistance? ──► YES ──► [ CULLED BY DISTANCE ]
                               │ NO
                               ▼
                 Is Line of Sight Occluded?
                               │
                ┌──────────────┴──────────────┐
                │ YES                         │ NO
                ▼                             ▼
    [ CULLED BY OCCLUSION ]         [ REPLICATE FULL TRANSFORM ]
    (Zero coordinates sent)         (Full bones & physics sent)
                │
                ▼
     Target Making Sound &&
      Dist <= SoundRadius?
                │
        ┌───────┴───────┐
        │ YES           │ NO
        ▼               ▼
[ REPLICATE ACOUSTIC ]  [ ZERO REPLICATION ]
(Audio cue packet only;
 no player identity/bones)
```

### 3.2 Server Integration Example (C++)

```cpp
#include "noescape/server/server_integration.hpp"

using namespace noescape::server;

// Initialize filter on server startup
ServerEspFilter espFilter;

// Load static map occluders (walls, terrain, buildings)
void LoadMapGeometry() {
    // Add thick concrete wall: min=(x1, y1, z1), max=(x2, y2, z2), allows_bullet_penetration=false
    espFilter.AddOccluder(OccluderBox{-50.0f, 19.5f, -10.0f, 50.0f, 20.5f, 10.0f, false});
}

// Called in server network replication pass per client
void NetworkReplicationTick(const Player& observerPlayer, const std::vector<Player>& allPlayers) {
    ObserverState observer;
    observer.player_id = observerPlayer.id;
    observer.x = observerPlayer.pos.x;
    observer.y = observerPlayer.pos.y;
    observer.z = observerPlayer.pos.z + 1.6f; // Eye level

    for (const auto& targetPlayer : allPlayers) {
        if (targetPlayer.id == observerPlayer.id) continue;

        TargetEntityState target;
        target.entity_id = targetPlayer.id;
        target.x = targetPlayer.pos.x;
        target.y = targetPlayer.pos.y;
        target.z = targetPlayer.pos.z + 1.0f; // Center of mass
        target.is_making_sound = targetPlayer.is_sprinting || targetPlayer.is_firing;
        target.sound_radius = targetPlayer.is_firing ? 60.0f : 15.0f;

        ReplicationDecision decision = espFilter.EvaluateEntityReplication(observer, target);

        if (decision.replicate_full_transform) {
            // Target is visible: send position, rotation, velocity, and bone animations
            SendFullTransformPacket(observerPlayer, targetPlayer);
        } else if (decision.replicate_acoustic_cue_only) {
            // Target is hidden behind wall, but making sound:
            // Send ONLY an acoustic footstep/gunfire sound event with attenuated coordinates.
            // NEVER send player bounding box, health, weapon, or bone transforms!
            SendAcousticCuePacket(observerPlayer, targetPlayer.pos, targetPlayer.sound_volume);
        } else {
            // Target is completely occluded and silent: DROP packet entirely.
            // Client receives NOTHING.
        }
    }
}
```

---

## 4. Authoritative Movement & Speedhack Validation

Clients are prone to tick manipulation, lag switches, and teleport hacks. The dedicated server validates each incoming position delta:

$$\text{ObservedSpeed} = \frac{\sqrt{\Delta x^2 + \Delta y^2 + \Delta z^2}}{\Delta t}$$

```cpp
auto violation = espFilter.ValidatePlayerMovement(
    player.id,
    player.last_pos.x, player.last_pos.y, player.last_pos.z, player.last_timestamp_ms,
    player.curr_pos.x, player.curr_pos.y, player.curr_pos.z, player.curr_timestamp_ms,
    /*max_allowed_speed_mps=*/ 9.5f // Maximum allowed sprint speed with latency tolerance
);

if (violation) {
    // Flag speedhack/teleport attempt:
    // Reject position delta, snap player back to last_pos, and log violation
    SnapPlayerBack(player, player.last_pos);
    RecordServerSecurityEvent(*violation);
}
```

---

## 5. Server-Authoritative Cryptographic Attestation

To prove that a game client has not been modified or replaced with a hacked bot:
1. The server generates a random 32-byte cryptographic challenge nonce:
   $$\text{ChallengeNonce} = \text{CSPRNG}(32)$$
2. The server dispatches the nonce to the client over the secure channel.
3. The client computes the attestation digest over its verified code section:
   $$\text{AttestationDigest} = \text{CryptoUtil::Sha256}(\text{TextSectionBytes} \mathbin{\Vert} \text{ChallengeNonce})$$
4. The server validates the digest against the expected build hash:
   - If the digest matches: Session is marked `SERVER_VERIFIED`.
   - If the digest fails or times out: Session is rejected (`SERVER_SESSION_REJECT`).
