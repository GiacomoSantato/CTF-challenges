# 🧑‍🍳 Top Chef — Molecon Finals 2025

I wrote this challenge for **Molecon CTF Finals 2025**. The **PTM team** is always an extended family and Turin is always like a second (first?) home to **about:blankets**. This is why I feel that it's become tradition to cook up some weird crypto whenever we’re around. So here’s *Top Chef*, a challenge full of dishes, signatures, and the occasional 🍍ananas pizza.

# crypto - Top Chef
*Challenge*
* Author: Sant
* Solves: 2 (Tower of Hanoi and PIG SEK@1)
* Points: 381

> Italians are always so picky about which dishes are the best. Maybe it’s time to show them that there’s a new chef in town.


#### Challenge details

### 🔐 The Cryptographic Scheme

At its core, the challenge implements a **threshold Schnorr-like signature scheme** over an elliptic curve. The player is given one secret key share and must collaborate with simulated “other members” to produce valid signatures. Each signature is computed via a Fiat–Shamir transformation, using a shared generator \( G \), a combined public key \( PK = \sum \text{pk}_i \), and random commitments \( R = \sum \text{r}_i G \).

When the player proposes a new dish, the other members generate their commitments, and the player must submit their own to complete the round. The signature returned encodes all but the player's own secret contribution. 

The objective is to forge a signature on the message **Ananas Pizza** that other members would never agree to sign. 


The secret keys are shared additively.
````python
#server.py
self.sk= [randint(1,self.q) for _ in range(self.N)]
self.SK= sum(self.sk) % self.q

self.pk = [ sk_i*self.G for sk_i in self.sk]
self.PK = sum(self.pk)
````

The signaure is obtained classicly as in most Schnorr-like signatures.
````python
#server.py
s = [ (self.t[dish_num][i] + c*self.sk[i+1])%self.q for i in range(self.N-1)]
````

This should suggest that the ROS attack, with some modification, should apply to this design.
Unfortunately the max number of queries (376) is smaller than the bit size of the order of the elliptic curve (511).
Moreover, using Wagner to cover the missing dimensions is difficult because the hash function is artificially slowed-down.

````python
#server.py
def random_oracle(R,m):
    to_hash=str(self.G.xy()[0])+str(self.PK.xy()[0])+str(R.xy()[0])+m
    hash=hashlib.blake2b(to_hash.encode()).digest()
    for _ in range(10000): hash=hashlib.blake2b(hash).digest()
    return int.from_bytes(hash,"big")
````



> 💡 **Small Design Note**

This challenge is loosely inspired by the **improved ROS attack** I’ve been working on in my research. Recognizing the ROS structure (or a disguised variant of it) was intentionally part of the solve path.

That said, I'm starting to realize people are picking up on the fact that I write for Molecon. So for future challenges, I’ll either attach the relevant paper links directly, or avoid basing the core idea on my own research, just to dodge easy OSINT.

Nonetheless, I've heard that almost every team was able to find the paper, so the link with the ROS attack was clear enough.

#### 🧠 Solve

The attack is substantially the same as the one used against blind Schnorr signatures described in [this famous paper](https://eprint.iacr.org/2020/945). That work even discusses possible adaptations of the attack to threshold schemes, though it doesn't provide concrete implementations.

The core idea is to exploit **concurrency**: you craft challenges that are all based on the same active commitments, so that the responses from different rounds are meaningfully related. This structure lets you reuse information from the final signatures in a coordinated way to forge a new one.

Since the attack is well-known, I won’t describe it in full detail here. But briefly: by constructing your queries in a structured way, you can ensure that **each signature response reveals one "bit" of information**. Then, when you're later asked to respond to a fresh challenge, you can **decompose it bit-by-bit** and reconstruct a valid response using the signatures you've collected.

One of the tricky parts in adapting this attack to the *threshold* setting is how to handle the final signature forgery.

### 📜 In Classic ROS:

Once the decomposition is done, the attacker combines previous transcripts **as-is**:

````python
# Old ROS – blind Schnorr
R_forge = inner_product(coeffs, R_list)
s_forge = inner_product(coeffs, s_list)
````

Here, the attacker doesn’t need to know any secret key, they’re just summing precomputed responses that already include the full secret. The forgery is a **pure linear recombination** of valid signatures.

### 🍍 In Top Chef:

The attacker *only* knows partial responses $s_i$, the part signed by the other members.

So after decomposition, they must **complete** the signature by adding their own contribution explicitly:

````python
# Top Chef
s_forge = inner_product(coeffs, s_list)          # from the other signers
        + SK_atk * c_to_decompose                # attacker’s missing part
````

This is the first difference:

* In **classic ROS**, you reuse entire signatures.
* In **Top Chef**, you must *actively finish* each signature using your share of the secret key, including the forged one.

As mentioned earlier, another limtation is that the number of concurrent sessions is capped at **376**, whereas a classical ROS attack over a 511-bit group would require **at least 511 queries** to cover every bit of the target challenge via binary decomposition.

Classically, this gap is bridged using the **Wagner algorithm** to reduce the effective dimension. The idea is to find collisions between subsets of challenges and compress the bit length required to perform the decomposition. But in this case, the number of missing dimensions is too large, and Wagner becomes computationally infeasible, especially with the deliberately slowed-down hash oracle.

To overcome this, the attack applies the technique from [Dimensional eROSion](https://eprint.iacr.org/2025/306):  
a **generalized decomposition strategy** that breaks the forged challenge not in base-2, but in **higher bases**, 3, 4, 5, and so on.

Again, briefly, the idea behind this is that instead of needing one query per bit (as in base-2), we want to represent the target challenge in a higher base, which requires **fewer digits**.

While a setup that allows us to reuse previous challenges to decompose a new one in base-2 only needs to solve a linear system (and can be done exactly), using base-3 (or any higher base) doesn't permit that exact structure. Instead, we can create a setup that enables an **approximate decomposition** of a new challenge.

The decomposition now works by constructing an appropriate lattice and solving a **closest vector problem**, where the target vector corresponds to the desired digit values — for example, something like \((0 \cdot 3^k,\ 1 \cdot 3^k,\ 2 \cdot 3^k)\). We then replace the digit in the decomposition with the coordinate of the closest vector. The distance between the exact target and our closest lattice vector will typically be around \(p^{1/2}\), which gives us a **benign approximation** for many of the top digits.

Luckily, if we manage the added errors carefully, we can:
- decompose the **most significant digits** approximately (in base-3 or higher),
- **track the approximation errors**, and
- decompose the residual value again in base-2 with exact final steps.

By chaining together decompositions in **decreasing bases** (e.g., base-7 → base-4 → base-2), the attack reduces the number of required sessions from ≈log₂(p) to **~0.726 ·**

For the concrete solution we decide which powers to use in which basis to decompose the number by using the same helping function that is in the paper 

````python
def multibase(input_number, pows):
    temp_number = ZZ(input_number)
    digits=[]
    for base in pows[::-1]:
        digits=[ temp_number// base ] +digits
        temp_number = temp_number % base
    assert inner_product( digits,pows) == input_number
    return digits
````

This function gives us a clean multibase decomposition of the forged challenge. In our case, it produces a decomposition of length slightly above the session limit, around 379 digits, if I remember correctly.
To overcome this mismatch (we're only allowed 376 sessions), there are three possible strategies:

1. Use Wagner’s algorithm to eliminate the top dimensions. This is the theoretically cleanest approach, compressing the input space until only the necessary digits remain.

2. Manually tweak the decomposition to use slightly fewer digits. This involves choosing a shorter base configuration that doesn't come from multibase() directly, but still yields a good success probability for decomposition.

3. Rerandomize the forged challenge until the top digits are zero. This is the most pragmatic approach. Unfortunately, since the top three digits are in base-11, the probability of them being zero is not so big, so a good candidate appears every ~60 seconds on average.

From a theory perspective, using Wagner is best. From a practical perspective, simple rerandomization works fine.


### 📝 Final Comments

I didn’t bother using secure randomness in this challenge because I felt it wasn’t exploitable enough to lead to any meaningful alternative solution.  
But in hindsight, this confused some teams who spent time chasing vulnerabilities that weren’t actually there. 

Next time, I’ll try to avoid leaving half-open paths like that.  
I’ve come to believe that having a **clear cryptographic target** is really important in challenges, especially in 24-hour CTFs.  
Hiding the actual vulnerability among a bunch of unrelated or fake ones just doesn’t feel fair (or fun) in the context of crypto CTFs.

That said, I had a lot of fun writing *Top Chef*, and I’m happy it ended up being both solvable and memorable.  
Next time, I’ll also be there in person at the next CTF, hopefully to watch the teams tackle my challenge live (and maybe suffer just a little 😈).
