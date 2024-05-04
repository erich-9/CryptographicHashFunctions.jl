const lib = libsodium_jll.libsodium

const supports_streaming = false

const algoid_mapping = Dict(P.SHA256 => (:sha256, 64), P.SHA512 => (:sha512, 128))

struct SodiumHash
    statebytes::Csize_t
    bytes::Csize_t
    init::Ptr{Cvoid}
    update::Ptr{Cvoid}
    final::Ptr{Cvoid}

    function SodiumHash(algoname)
        syms = map(x -> _sym(algoname, x), (:statebytes, :bytes, :init, :update, :final))
        new((@ccall $x()::Csize_t for x ∈ first(syms, 2))..., last(syms, 3)...)
    end
end

const Chash_state = Ptr{Cvoid}

function _sym(algoname, suffix; kwargs...)
    Base.Libc.Libdl.dlsym(
        libsodium_jll.libsodium_handle,
        Symbol(:crypto_hash_, algoname, :_, suffix);
        kwargs...,
    )
end

function is_available(algoid_external)
    (algoname, _) = algoid_external

    !isnothing(_sym(algoname, :bytes; throw_error = false))
end

struct Algorithm{T}
    identifier::T
    blocksize::Int
    digestsize::Int
    sh::SodiumHash

    function Algorithm(algoid::T, algoid_external) where {T}
        (algoname, blocksize) = algoid_external
        sh = SodiumHash(algoname)

        new{T}(algoid, blocksize, sh.bytes, sh)
    end
end

mutable struct Context{T} <: P.Context{T}
    algo::Algorithm{T}
    state::Vector{UInt8}

    function Context(algoid::T) where {T}
        algo = algorithms[algoid]
        state = Vector{UInt8}(undef, algo.sh.statebytes)

        res = new{T}(algo, state)
        P.reset!(res)
        res
    end

    function Context(ctx::Context{T}) where {T}
        new{T}(ctx.algo, copy(ctx.state))
    end
end

Base.copy(ctx::Context) = Context(ctx)

function P.reset!(ctx::Context)
    rc = @ccall $(ctx.algo.sh.init)(ctx.state::Chash_state)::Cint
    rc == 0 || error("crypto_hash_*_init failed")

    nothing
end

function P.update!(ctx::Context, data::AbstractVector{UInt8}, len::Integer = length(data))
    rc = @ccall $(ctx.algo.sh.update)(
        ctx.state::Chash_state,
        data::Ptr{Cuchar},
        len::Culonglong,
    )::Cint
    rc == 0 || error("crypto_hash_*_update failed")

    nothing
end

function P.digest!(ctx::Context)
    len = ctx.algo.digestsize
    res = Vector{UInt8}(undef, len)

    rc = @ccall $(ctx.algo.sh.final)(
        ctx.state::Chash_state,
        res::Ptr{Cuchar},
        len::Culonglong,
    )::Cint
    rc == 0 || error("crypto_hash_*_final failed")

    res
end
