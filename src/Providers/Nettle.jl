const lib = Nettle_jll.libnettle

const supports_streaming = false

const algoid_mapping = Dict(
    P.GOST94 => "gosthash94",
    P.GOST94CP => "gosthash94cp",
    P.MD2 => "md2",
    P.MD4 => "md4",
    P.MD5 => "md5",
    P.RIPEMD160 => "ripemd160",
    P.SHA1 => "sha1",
    P.SHA224 => "sha224",
    P.SHA256 => "sha256",
    P.SHA384 => "sha384",
    P.SHA512 => "sha512",
    P.SHA512_224 => "sha512_224",
    P.SHA512_256 => "sha512_256",
    P.SHA3_224 => "sha3_224",
    P.SHA3_256 => "sha3_256",
    P.SHA3_384 => "sha3_384",
    P.SHA3_512 => "sha3_512",
    P.SM3 => "sm3",
    P.STRIBOG256 => "streebog256",
    P.STRIBOG512 => "streebog512",
)

struct NettleHash
    name::Cstring
    context_size::Cuint
    digest_size::Cuint
    block_size::Cuint
    init::Ptr{Cvoid}
    update::Ptr{Cvoid}
    digest::Ptr{Cvoid}

    function NettleHash(algoid_external)
        unsafe_load(convert(Ptr{NettleHash}, _sym(algoid_external)))
    end
end

const Chash_ctx = Ptr{Cvoid}

function _sym(algoid_external; kwargs...)
    Base.Libc.Libdl.dlsym(
        Nettle_jll.libnettle_handle,
        Symbol(:nettle_, algoid_external);
        kwargs...,
    )
end

function is_available(algoid_external)
    !isnothing(_sym(algoid_external; throw_error = false))
end

mutable struct Algorithm{T}
    identifier::T
    blocksize::Int
    digestsize::Int
    nh::NettleHash

    function Algorithm(algoid::T, algoid_external) where {T}
        nh = NettleHash(algoid_external)

        new{T}(algoid, nh.block_size, nh.digest_size, nh)
    end
end

mutable struct Context{T} <: P.Context{T}
    algo::Algorithm{T}
    ctx::Vector{UInt8}

    function Context(algoid::T) where {T}
        algo = algorithms[algoid]
        ctx = Vector{UInt8}(undef, algo.nh.context_size)
        @ccall $(algo.nh.init)(ctx::Chash_ctx)::Cvoid

        new{T}(algo, ctx)
    end

    function Context(ctx::Context{T}) where {T}
        new{T}(ctx.algo, copy(ctx.ctx))
    end
end

Base.copy(ctx::Context) = Context(ctx)

function P.reset!(ctx::Context)
    @ccall $(ctx.algo.nh.init)(ctx.ctx::Chash_ctx)::Cvoid
end

function P.update!(ctx::Context, data::AbstractVector{UInt8}, len::Integer = length(data))
    @ccall $(ctx.algo.nh.update)(ctx.ctx::Chash_ctx, len::Csize_t, data::Ptr{Cuchar})::Cvoid
end

function P.digest!(ctx::Context)
    len = ctx.algo.digestsize
    res = Vector{UInt8}(undef, len)

    @ccall $(ctx.algo.nh.digest)(ctx.ctx::Chash_ctx, len::Csize_t, res::Ptr{Cuchar})::Cvoid

    res
end
