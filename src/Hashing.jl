module Hashing

export digest, hmac_digest
export HMAC, XOF, context, reset!, update!, digest!

@enum HashAlgorithmID begin
    BLAKE2B_160
    BLAKE2B_256
    BLAKE2B_384
    BLAKE2B_512
    BLAKE2S_128
    BLAKE2S_160
    BLAKE2S_224
    BLAKE2S_256
    GOST94
    GOST94CP
    MD4
    MD5
    RIPEMD160
    SHA1
    SHA224
    SHA256
    SHA384
    SHA512
    SHA512_224
    SHA512_256
    SHA3_224
    SHA3_256
    SHA3_384
    SHA3_512
    SM3
    STRIBOG256
    STRIBOG512
    TIGER
    TIGER1
    TIGER2
    WHIRLPOOL
end

@enum XOFAlgorithmID begin
    SHAKE128
    SHAKE256
end

const AlgorithmIDs = (HashAlgorithmID, XOFAlgorithmID)
const AlgorithmID = Union{AlgorithmIDs...}

abstract type Context{T} end

function reset! end
function update! end
function digest! end

include("./OpenSSL.jl")
include("./Libgcrypt.jl")

const providers = (OpenSSL, Libgcrypt)
const default_provider = first(providers)

bytes(data::AbstractVector{UInt8}) = data
bytes(data::AbstractString) = codeunits(data)
bytes(data::IO) = read(data)
bytes(data) = collect(UInt8, data)

function digest(algoid, data, args...; provider = default_provider, kwargs...)
    digest!(context(algoid, data; provider, kwargs...), args...)
end

function hmac_digest(algoid, key, data; provider = default_provider, kwargs...)
    hmac = HMAC(algoid, key; provider)
    update!(hmac, data; kwargs...)
    digest!(hmac)
end

struct HMAC
    outer_key::Vector{UInt8}
    ctx::Context{HashAlgorithmID}

    function HMAC(algoid, key; provider = default_provider)
        blocksize = provider.algorithms[algoid].blocksize
        key⁰ = bytes(key)
        key¹ = zeros(UInt8, blocksize)
        copyto!(key¹, length(key⁰) > blocksize ? digest(algoid, key⁰; provider) : key⁰)
        new(key¹ .⊻ 0x5c, context(algoid, key¹ .⊻ 0x36; provider))
    end
end

struct XOF
    ctx::Context{XOFAlgorithmID}

    function XOF(algoid, data; provider = default_provider, kwargs...)
        new(context(algoid, data; provider, kwargs...))
    end
end

function context(algoid; provider = default_provider)
    provider.Context(algoid)
end

function context(algoid, data; provider = default_provider, kwargs...)
    ctx = provider.Context(algoid)
    update!(ctx, data; kwargs...)
    ctx
end

function update!(hmac::HMAC, data; kwargs...)
    update!(hmac.ctx, data; kwargs...)
end

function update!(ctx::Context, io::IO; chunksize = 4096)
    data = Vector{UInt8}(undef, chunksize)
    while !eof(io)
        len = readbytes!(io, data)
        update!(ctx, data, len)
    end
end

function update!(ctx::Context, tpl::NTuple{N, UInt8}) where {N}
    ref = Ref(tpl)
    GC.@preserve ref begin
        ptr = Base.unsafe_convert(Ptr{UInt8}, ref)
        data = unsafe_wrap(Vector{UInt8}, ptr, N)
        update!(ctx, data)
    end
end

function update!(ctx::Context, str::AbstractString)
    update!(ctx, bytes(str))
end

function digest!(hmac::HMAC)
    inner_digest = digest!(hmac.ctx)
    reset!(hmac.ctx)
    update!(hmac.ctx, hmac.outer_key)
    update!(hmac.ctx, inner_digest)
    digest!(hmac.ctx)
end

function digest!(xof::XOF, len::Integer)
    digest!(xof.ctx, len)
end

begin
    streaming_providers = filter(x -> x.supports_streaming, providers)

    select_provider(algoid, providers) =
        let i = findfirst(x -> haskey(x.algoid_mapping, algoid), providers)
            isnothing(i) ? nothing : providers[i]
        end

    for algoids ∈ AlgorithmIDs, algoid ∈ instances(algoids)
        H = Symbol(algoid)
        h = Symbol(lowercase(String(H)))

        provider = select_provider(algoid, providers)
        isnothing(provider) && continue

        @eval begin
            export $H, $h

            $h(data, args...; provider = $provider, kwargs...) =
                digest($algoid, data, args...; provider, kwargs...)
        end

        if algoid isa HashAlgorithmID
            hmac_h = Symbol(:hmac_, h)

            @eval begin
                export $hmac_h

                $hmac_h(key, data; provider = $provider, kwargs...) =
                    hmac_digest($algoid, key, data; provider, kwargs...)
            end
        end

        if algoid isa XOFAlgorithmID
            provider = select_provider(algoid, streaming_providers)

            if !isnothing(provider)
                @eval begin
                    $h(data; provider = $provider, kwargs...) =
                        XOF($algoid, data; provider, kwargs...)
                end
            end
        end
    end
end

end # module
