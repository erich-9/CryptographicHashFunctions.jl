module _OpenSSL

import ..CryptographicHashFunctions as P
import Base.Libc.Libdl: dlopen, dlsym
import OpenSSL_jll

const lib = OpenSSL_jll.libcrypto

const supports_streaming =
    !isnothing(dlsym(dlopen(lib), :EVP_DigestSqueeze; throw_error = false))

const algoid_mapping = Dict(
    P.BLAKE2B_512 => "BLAKE2B-512",
    P.BLAKE2S_256 => "BLAKE2S-256",
    P.MD5 => "MD5",
    P.RIPEMD160 => "RIPEMD160",
    P.SHA1 => "SHA1",
    P.SHA224 => "SHA224",
    P.SHA256 => "SHA256",
    P.SHA384 => "SHA384",
    P.SHA512 => "SHA512",
    P.SHA512_224 => "SHA512-224",
    P.SHA512_256 => "SHA512-256",
    P.SHA3_224 => "SHA3-224",
    P.SHA3_256 => "SHA3-256",
    P.SHA3_384 => "SHA3-384",
    P.SHA3_512 => "SHA3-512",
    P.SHAKE128 => "SHAKE128",
    P.SHAKE256 => "SHAKE256",
    P.SM3 => "SM3",
)

const Cmd = Ptr{Cvoid}
const Cmd_ctx = Ptr{Cvoid}

function available(algoid_external)
    md = @ccall lib.EVP_MD_fetch(
        C_NULL::Ptr{Cvoid},
        algoid_external::Cstring,
        C_NULL::Ptr{Cvoid},
    )::Cmd

    res = md != C_NULL

    @ccall lib.EVP_MD_free(md::Cmd)::Cvoid

    res
end

mutable struct Algorithm{T}
    identifier::T
    blocksize::Int
    digestsize::Int
    md::Cmd

    function Algorithm(algoid::T, algoid_external) where {T}
        md = @ccall lib.EVP_MD_fetch(
            C_NULL::Ptr{Cvoid},
            algoid_external::Cstring,
            C_NULL::Ptr{Cvoid},
        )::Cmd
        md != C_NULL || error("EVP_MD_fetch failed for $algoid")

        blocksize = @ccall lib.EVP_MD_get_block_size(md::Cmd)::Cint
        digestsize = @ccall lib.EVP_MD_get_size(md::Cmd)::Cint

        finalizer(new{T}(algoid, blocksize, digestsize, md)) do x
            @ccall lib.EVP_MD_free(x.md::Cmd)::Cvoid
        end
    end
end

mutable struct Context{T} <: P.Context{T}
    algo::Algorithm{T}
    ctx::Cmd_ctx
    finalized::Bool

    function Context(algoid::T) where {T}
        algo = algorithms[algoid]
        ctx = @ccall lib.EVP_MD_CTX_new()::Cmd_ctx
        ctx != C_NULL || error("EVP_MD_CTX_new failed")

        res = new{T}(algo, ctx)
        P.reset!(res)

        finalizer(res) do x
            @ccall lib.EVP_MD_CTX_free(x.ctx::Cmd_ctx)::Cvoid
        end
    end

    function Context(ctx::Context)
        res = Context(ctx.algo.identifier)

        rc = @ccall lib.EVP_MD_CTX_copy_ex(res.ctx::Cmd_ctx, ctx.ctx::Cmd_ctx)::Cint
        rc == 1 || error("EVP_MD_CTX_copy_ex failed")

        res
    end
end

Base.copy(ctx::Context) = Context(ctx)

function P.reset!(ctx::Context)
    rc = @ccall lib.EVP_DigestInit_ex(
        ctx.ctx::Cmd_ctx,
        ctx.algo.md::Cmd,
        C_NULL::Ptr{Cvoid},
    )::Cint
    rc == 1 || error("EVP_DigestInit_ex failed")

    ctx.finalized = false

    nothing
end

function P.update!(ctx::Context, data::AbstractVector{UInt8}, len::Integer = length(data))
    rc =
        @ccall lib.EVP_DigestUpdate(ctx.ctx::Cmd_ctx, data::Ptr{Cuchar}, len::Csize_t)::Cint
    rc == 1 || error("EVP_DigestUpdate failed")

    nothing
end

function P.digest!(ctx::Context{P.HashAlgorithmID})
    res = Vector{UInt8}(undef, ctx.algo.digestsize)

    ctx.finalized && error("multiple calls to digest! not allowed")
    ctx.finalized = true

    rc = @ccall lib.EVP_DigestFinal_ex(
        ctx.ctx::Cmd_ctx,
        res::Ptr{Cuchar},
        C_NULL::Ptr{Cvoid},
    )::Cint
    rc == 1 || error("EVP_DigestFinal_ex failed")

    res
end

if supports_streaming
    function P.digest!(ctx::Context{P.XOFAlgorithmID}, len::Integer)
        res = Vector{UInt8}(undef, len)

        rc = @ccall lib.EVP_DigestSqueeze(
            ctx.ctx::Cmd_ctx,
            res::Ptr{Cuchar},
            len::Csize_t,
        )::Cint
        rc == 1 || error("EVP_DigestSqueeze failed")

        res
    end
else
    function P.digest!(ctx::Context{P.XOFAlgorithmID}, len::Integer)
        res = Vector{UInt8}(undef, len)

        ctx.finalized && error("multiple calls to digest! require OpenSSL ^3.3")
        ctx.finalized = true

        rc = @ccall lib.EVP_DigestFinalXOF(
            ctx.ctx::Cmd_ctx,
            res::Ptr{Cuchar},
            len::Csize_t,
        )::Cint
        rc == 1 || error("EVP_DigestFinalXOF failed")

        res
    end
end

begin
    for (algoid, algoid_external) ∈ copy(algoid_mapping)
        if !available(algoid_external)
            delete!(algoid_mapping, algoid)
            @info "OpenSSL: $algoid not provided"
        end
    end

    const algorithms = Dict{P.AlgorithmID, Algorithm}()

    function __init__()
        for (algoid, algoid_external) ∈ algoid_mapping
            algorithms[algoid] = Algorithm(algoid, algoid_external)
        end
    end
end

end # module
