const lib = Botan_AppleGCC_jll.libbotan

const supports_streaming = false

const algoid_mapping = Dict(
    P.BLAKE2B_160 => "BLAKE2b(160)",
    P.BLAKE2B_256 => "BLAKE2b(256)",
    P.BLAKE2B_384 => "BLAKE2b(384)",
    P.BLAKE2B_512 => "BLAKE2b(512)",
    P.BLAKE2S_128 => "BLAKE2s(128)",
    P.BLAKE2S_160 => "BLAKE2s(160)",
    P.BLAKE2S_224 => "BLAKE2s(224)",
    P.BLAKE2S_256 => "BLAKE2s(256)",
    P.GOST94CP => "GOST-R-34.11-94",
    P.MD5 => "MD5",
    P.RIPEMD160 => "RIPEMD-160",
    P.SHA1 => "SHA-1",
    P.SHA224 => "SHA-224",
    P.SHA256 => "SHA-256",
    P.SHA384 => "SHA-384",
    P.SHA512 => "SHA-512",
    P.SHA512_256 => "SHA-512-256",
    P.SHA3_224 => "SHA-3(224)",
    P.SHA3_256 => "SHA-3(256)",
    P.SHA3_384 => "SHA-3(384)",
    P.SHA3_512 => "SHA-3(512)",
    P.SKEIN512_256 => "Skein-512(256)",
    P.SKEIN512_512 => "Skein-512(512)",
    P.SM3 => "SM3",
    P.STRIBOG256 => "Streebog-256",
    P.STRIBOG512 => "Streebog-512",
    P.WHIRLPOOL => "Whirlpool",
)

const Chash_t = Ptr{Cvoid}

function _init(algoname; throw_error = true)
    hash = Ref{Chash_t}()

    rc = @ccall lib.botan_hash_init(hash::Ptr{Chash_t}, algoname::Cstring, 0::Cuint)::Cint

    if rc != 0
        throw_error && error("botan_hash_init failed for '$algoname'")
        nothing
    else
        hash
    end
end

function _destroy(hash)
    rc = @ccall lib.botan_hash_destroy(hash[]::Chash_t)::Cint
    rc == 0 || error("botan_hash_destroy failed")
end

function is_available(algoname)
    hash = _init(algoname; throw_error = false)

    if isnothing(hash)
        false
    else
        _destroy(hash)
        true
    end
end

struct Algorithm{T}
    identifier::T
    blocksize::Int
    digestsize::Int
    algoname::String

    function Algorithm(algoid::T, algoid_external) where {T}
        hash = _init(algoid_external)

        blocksize = Ref{Csize_t}()
        rc =
            @ccall lib.botan_hash_block_size(hash[]::Chash_t, blocksize::Ptr{Csize_t})::Cint
        rc == 0 || error("botan_hash_block_size failed")

        digestsize = Ref{Csize_t}()
        rc = @ccall lib.botan_hash_output_length(
            hash[]::Chash_t,
            digestsize::Ptr{Csize_t},
        )::Cint
        rc == 0 || error("botan_hash_output_length failed")

        _destroy(hash)

        new{T}(algoid, blocksize[], digestsize[], algoid_external)
    end
end

mutable struct Context{T} <: P.Context{T}
    algo::Algorithm{T}
    hash::Ref{Chash_t}

    function Context(algoid::T) where {T}
        algo = algorithms[algoid]
        hash = _init(algo.algoname)

        finalizer(new{T}(algo, hash)) do x
            _destroy(x.hash)
        end
    end

    function Context(ctx::Context{T}) where {T}
        algo = ctx.algo
        hash = Ref{Chash_t}()

        rc = @ccall lib.botan_hash_copy_state(hash::Ptr{Chash_t}, ctx.hash[]::Chash_t)::Cint
        rc == 0 || error("botan_hash_copy_state failed")

        finalizer(new{T}(algo, hash)) do x
            _destroy(x.hash)
        end
    end
end

Base.copy(ctx::Context) = Context(ctx)

function P.reset!(ctx::Context)
    rc = @ccall lib.botan_hash_clear(ctx.hash[]::Chash_t)::Cint
    rc == 0 || error("botan_hash_clear failed")

    nothing
end

function P.update!(ctx::Context, data::AbstractVector{UInt8}, len::Integer = length(data))
    rc = @ccall lib.botan_hash_update(
        ctx.hash[]::Chash_t,
        data::Ptr{Cuchar},
        len::Csize_t,
    )::Cint
    rc == 0 || error("botan_hash_update failed")

    nothing
end

function P.digest!(ctx::Context)
    len = ctx.algo.digestsize
    res = Vector{UInt8}(undef, len)

    rc = @ccall lib.botan_hash_final(ctx.hash[]::Chash_t, res::Ptr{Cuchar})::Cint
    rc == 0 || error("botan_hash_final failed")

    res
end
