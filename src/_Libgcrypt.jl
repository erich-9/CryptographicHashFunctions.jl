module _Libgcrypt

import ..CryptographicHashFunctions as P
import Libgcrypt_jll

const lib = Libgcrypt_jll.libgcrypt

const supports_streaming = true

const algoid_mapping = Dict(
    P.BLAKE2B_160 => (321, 128),
    P.BLAKE2B_256 => (320, 128),
    P.BLAKE2B_384 => (319, 128),
    P.BLAKE2B_512 => (318, 128),
    P.BLAKE2S_128 => (325, 64),
    P.BLAKE2S_160 => (324, 64),
    P.BLAKE2S_224 => (323, 64),
    P.BLAKE2S_256 => (322, 64),
    P.GOST94 => (308, 32),
    P.GOST94CP => (311, 32),
    P.MD4 => (301, 64),
    P.MD5 => (1, 64),
    P.RIPEMD160 => (3, 64),
    P.SHA1 => (2, 64),
    P.SHA224 => (11, 64),
    P.SHA256 => (8, 64),
    P.SHA384 => (9, 128),
    P.SHA512 => (10, 128),
    # P.SHA512_224 => (328, 128),
    # P.SHA512_256 => (327, 128),
    P.SHA3_224 => (312, 144),
    P.SHA3_256 => (313, 136),
    P.SHA3_384 => (314, 104),
    P.SHA3_512 => (315, 72),
    P.SHAKE128 => (316, 168),
    P.SHAKE256 => (317, 136),
    P.STRIBOG256 => (309, 64),
    P.STRIBOG512 => (310, 64),
    P.TIGER => (6, 64),
    P.TIGER1 => (306, 64),
    P.TIGER2 => (307, 64),
    P.WHIRLPOOL => (305, 64),
)

const Cgcry_ctl_cmds = Cint
const Cgcry_error_t = Cuint
const Cgcry_md_algos = Cint
const Cgcry_md_hd_t = Ptr{Cvoid}

function available(algoid_external)
    (algono, _) = algoid_external

    rc = @ccall lib.gcry_md_algo_info(
        algono::Cgcry_md_algos,
        8::Cgcry_ctl_cmds,
        C_NULL::Ptr{Cvoid},
        0::Csize_t,
    )::Cgcry_error_t

    rc == 0
end

struct Algorithm{T}
    identifier::T
    blocksize::Int
    digestsize::Int
    algono::Cgcry_md_algos

    function Algorithm(algoid::T, algoid_external) where {T}
        (algono, blocksize) = algoid_external

        digestsize = @ccall lib.gcry_md_get_algo_dlen(algono::Cgcry_md_algos)::Cuint

        new{T}(algoid, blocksize, digestsize, algono)
    end
end

mutable struct Context{T} <: P.Context{T}
    algo::Algorithm{T}
    hd::Ref{Cgcry_md_hd_t}

    function Context(algoid::T) where {T}
        algo = algorithms[algoid]
        hd = Ref{Cgcry_md_hd_t}()

        rc = @ccall lib.gcry_md_open(
            hd::Ptr{Cgcry_md_hd_t},
            algo.algono::Cgcry_md_algos,
            0::Cuint,
        )::Cgcry_error_t
        rc == 0 || error("gcry_md_open failed for $algoid")

        finalizer(new{T}(algo, hd)) do x
            @ccall lib.gcry_md_close(x.hd[]::Cgcry_md_hd_t)::Cvoid
        end
    end

    function Context(ctx::Context{T}) where {T}
        algo = algorithms[ctx.algo.identifier]
        hd = Ref{Cgcry_md_hd_t}()

        rc = @ccall lib.gcry_md_copy(
            hd::Ptr{Cgcry_md_hd_t},
            ctx.hd[]::Cgcry_md_hd_t,
        )::Cgcry_error_t
        rc == 0 || error("gcry_md_copy failed")

        finalizer(new{T}(algo, hd)) do x
            @ccall lib.gcry_md_close(x.hd[]::Cgcry_md_hd_t)::Cvoid
        end
    end
end

Base.copy(ctx::Context) = Context(ctx)

function P.reset!(ctx::Context)
    @ccall lib.gcry_md_reset(ctx.hd[]::Cgcry_md_hd_t)::Cvoid
end

function P.update!(ctx::Context, data::AbstractVector{UInt8}, len::Integer = length(data))
    @ccall lib.gcry_md_write(
        ctx.hd[]::Cgcry_md_hd_t,
        data::Ptr{Cuchar},
        len::Csize_t,
    )::Cvoid
end

function P.digest!(ctx::Context{P.HashAlgorithmID})
    GC.@preserve ctx begin
        rv = @ccall lib.gcry_md_read(
            ctx.hd[]::Cgcry_md_hd_t,
            ctx.algo.algono::Cgcry_md_algos,
        )::Ptr{Cuchar}

        copy(unsafe_wrap(Vector{UInt8}, rv, ctx.algo.digestsize))
    end
end

function P.digest!(ctx::Context{P.XOFAlgorithmID}, len::Integer)
    res = Vector{UInt8}(undef, len)

    rc = @ccall lib.gcry_md_extract(
        ctx.hd[]::Cgcry_md_hd_t,
        ctx.algo.algono::Cgcry_md_algos,
        res::Ptr{Cuchar},
        len::Csize_t,
    )::Cgcry_error_t
    rc == 0 || error("gcry_md_extract failed")

    res
end

begin
    for (algoid, algoid_external) ∈ copy(algoid_mapping)
        if !available(algoid_external)
            delete!(algoid_mapping, algoid)
            @info "Libgcrypt: $algoid not provided"
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
