# Usage

First, load the package:

```@example usage
using Hashing
```

## High-Level

Working with the high-level interface is quite easy:

```@example usage
bytes2hex(sha3_224("Hash me!"))
```

Or, to compute the file hash (of an empty file named `filename`):

```@example usage
filename = tempname() # hide
touch(filename) # hide
bytes2hex(sha256(open(filename)))
```

Calculating HMAC's is similarly straightforward:

```@example usage
bytes2hex(hmac_sha256("some key", "some data"))
```

The backend used to do the hashing can be specified with the keyword argument `provider`:

```@example usage
sha256(""; provider = Hashing.OpenSSL) == sha256(""; provider = Hashing.Libgcrypt)
```

Extracting a fixed number of bytes from an extendable-output function can be done either in one go

```@example usage
bytes2hex(shake256("Hash and extract me!", 42))
```

or step by step:

```@example usage
xof = shake256("Hash and extract me!")
bytes2hex([digest!(xof, 10); digest!(xof, 10); digest!(xof, 22)])
```

## Low-Level

The low-level interface allows for more controlled operations.

Setting up a hash context, feeding it with some data, and finally computing the digest works as follows:

```@example usage
ctx = context(SHA3_224; provider = Hashing.Libgcrypt)
update!(ctx, "Hash ")
update!(ctx, "me!")
bytes2hex(digest!(ctx))
```

Or, in the case of an extendable-output function:

```@example usage
ctx = context(SHAKE256, "Hash and "; provider = Hashing.Libgcrypt)
update!(ctx, IOBuffer("extract me!"); buffersize = 2)
[bytes2hex(digest!(ctx, 15)) for i ∈ 1:5]
```

To avoid unneccessary allocations, it's sometimes useful to be able to copy or reset hash contexts:

```@example usage
ctx = context(SHA3_224, "Hash me!")
ctx_copy = copy(ctx)
reset!(ctx)
[bytes2hex(digest!(ctx)), bytes2hex(digest!(ctx_copy))]
```

Dealing with HMAC objects is similar:

```@example usage
hmac = HMAC(SHA256, "some key")
update!(hmac, "some data")
bytes2hex(digest!(hmac))
```
