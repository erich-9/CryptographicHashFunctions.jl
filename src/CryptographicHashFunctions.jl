module CryptographicHashFunctions

export digest, hmac_digest
export HMAC, context, reset!, update!, digest!

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
    MD2
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
    SKEIN512_256
    SKEIN512_512
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

"""
    reset!(ctx)

Reset the state of the hash context `ctx`. Afterwards, `ctx` can be used in the same way as
a freshly created hash context with the same associated algorithm.
"""
function reset! end

"""
    update!(obj, data[; provider, kwargs...])

Feed `data` into the hash context or HMAC object `obj`.

The argument `data` can be of type `AbstractVector{UInt8}`, `AbstractString`, `IO`, or any
other type that can be collected into a vector of bytes.

When reading `data` of type `IO`, the buffer size can be set with the optional keyword
argument `buffersize`.
"""
function update! end

"""
    digest!(obj)

Return the digest for the HMAC object or hash context `obj` of a hash algorithm.

Unless `reset!` is called before, further calls to `update!` or `digest!` are not allowed.

    digest!(ctx, len)

Return the next `len` bytes of the digest for the hash context `ctx` of an XOF algorithm.

Unless `reset!` is called before, further calls to `update!` are not allowed. If the
provider does not support streaming, further calls to `digest!` are forbidden, too.
"""
function digest! end

bytes(data::AbstractVector{UInt8}) = data
bytes(data::AbstractString) = codeunits(data)
bytes(data::IO) = read(data)
bytes(data) = collect(UInt8, data)

"""
    digest(algoid, data[; provider, kwargs...])

Return the digest of `data` computed with the hash algorithm `algoid`.
"""
function digest(algoid, data; provider = default_provider, kwargs...)
    digest!(context(algoid, data; provider, kwargs...))
end

"""
    digest(algoid, data, len[; provider, kwargs...])

Return the first `len` bytes of the digest of `data` computed with the XOF algorithm
`algoid`.
"""
function digest(algoid, data, len; provider = default_provider, kwargs...)
    digest!(context(algoid, data; provider, kwargs...), len)
end

"""
    hmac_digest(algoid, key, data[; provider, kwargs...])

Return the HMAC of `data` keyed with `key` computed with the hash algorithm `algoid`.
"""
function hmac_digest(algoid, key, data; provider = default_provider, kwargs...)
    hmac = HMAC(algoid, key; provider)
    update!(hmac, data; kwargs...)
    digest!(hmac)
end

"""
    HMAC(algoid, key[; provider])

Return a new HMAC object keyed with `key` for the hash algorithm `algoid`.
"""
struct HMAC
    outer_key::Vector{UInt8}
    ctx::Context{HashAlgorithmID}

    function HMAC(algoid, key; provider = default_provider)
        blocksize = provider[].algorithms[algoid].blocksize
        key⁰ = bytes(key)
        key¹ = zeros(UInt8, blocksize)
        copyto!(key¹, length(key⁰) > blocksize ? digest(algoid, key⁰; provider) : key⁰)
        new(key¹ .⊻ 0x5c, context(algoid, key¹ .⊻ 0x36; provider))
    end
end

"""
    context(algoid[; provider])

Return a new hash context for the algorithm `algoid`.
"""
function context(algoid; provider = default_provider)
    provider[].Context(algoid)
end

"""
    context(algoid, data[; provider, kwargs...])

Return a new hash context for the algorithm `algoid` and initialize it with `data`.
"""
function context(algoid, data; provider = default_provider, kwargs...)
    ctx = context(algoid; provider)
    update!(ctx, data; kwargs...)
    ctx
end

function update!(hmac::HMAC, data; kwargs...)
    update!(hmac.ctx, data; kwargs...)
end

function update!(ctx::Context, io::IO; buffersize = 4096)
    data = Vector{UInt8}(undef, buffersize)
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

function update!(ctx::Context, str)
    update!(ctx, bytes(str))
end

function digest!(hmac::HMAC)
    inner_digest = digest!(hmac.ctx)
    reset!(hmac.ctx)
    update!(hmac.ctx, hmac.outer_key)
    update!(hmac.ctx, inner_digest)
    digest!(hmac.ctx)
end

"""
Supported providers. Currently:

```julia-repl
julia> collect(CryptographicHashFunctions.providers)
4-element Vector{CryptographicHashFunctions.Provider}:
 OpenSSL
 Libgcrypt
 Nettle
 libsodium
 Botan_AppleGCC
```
"""
const providers = let ps = (:OpenSSL, :Libgcrypt, :Nettle, :libsodium, :Botan_AppleGCC)
    (M_ps, T_ps) = ((Symbol(x, :_, p) for p ∈ ps) for x ∈ (:M, :T))

    @eval @enum T_Provider $(T_ps...)

    struct Provider{T}
        Provider(T) = new{T}()
        Base.show(io::IO, ::Provider{T}) where {T} = print(io, String(Symbol(T))[3:end])
    end

    providers = Provider[]

    for (p, M_p, T_p) ∈ zip(ps, M_ps, T_ps)
        p_jll = Symbol(p, :_jll)
        p_str = String(p)

        @eval module $M_p

        import ..CryptographicHashFunctions as P
        import $p_jll

        if $p_jll.is_available()
            include("Providers/" * $p_str * ".jl")

            const algorithms = Dict{P.AlgorithmID, Algorithm}()

            for (algoid, algoid_external) ∈ copy(algoid_mapping)
                if !is_available(algoid_external)
                    delete!(algoid_mapping, algoid)
                    @info $p_str * ": $algoid not provided"
                end
            end

            function __init__()
                for (algoid, algoid_external) ∈ algoid_mapping
                    algorithms[algoid] = Algorithm(algoid, algoid_external)
                end
            end
        end

        end # module

        if @eval $M_p.$p_jll.is_available()
            @eval begin
                const $p = Provider($T_p)
                Base.getindex(::Provider{$T_p}) = $M_p

                push!($providers, $p)
                export $p
            end
        else
            @info "$p: provider not available"
        end
    end

    Tuple(providers)
end

"""
Default provider. Currently:

```julia-repl
julia> CryptographicHashFunctions.default_provider
OpenSSL
```
"""
const default_provider = first(providers)

begin
    const functions = (; id = [], hash = [], hmac = [], xof = [])

    const streaming_providers = filter(x -> x[].supports_streaming, providers)

    select_provider(algoid, providers) =
        let i = findfirst(x -> haskey(x[].algoid_mapping, algoid), providers)
            isnothing(i) ? nothing : providers[i]
        end

    for algoids ∈ AlgorithmIDs, algoid ∈ instances(algoids)
        H = Symbol(algoid)
        h = Symbol(lowercase(String(H)))

        provider = select_provider(algoid, providers)
        isnothing(provider) && continue

        @eval begin
            export $H, $h

            """
            Identifier for the $($H) algorithm.
            """
            $H
        end

        if algoid isa HashAlgorithmID
            hmac_h = Symbol(:hmac_, h)

            @eval begin
                export $hmac_h

                """
                    $($h)(data[; provider, kwargs...])

                Return the digest of `data` computed with the $($H) algorithm.
                """
                $h(data; provider = $provider, kwargs...) =
                    digest($algoid, data; provider, kwargs...)

                """
                    $($hmac_h)(key, data[; provider, kwargs...])

                Return the HMAC of `data` keyed with `key` computed with the $($H)
                algorithm.
                """
                $hmac_h(key, data; provider = $provider, kwargs...) =
                    hmac_digest($algoid, key, data; provider, kwargs...)

                push!(functions.hash, $h)
                push!(functions.hmac, $hmac_h)
            end
        end

        if algoid isa XOFAlgorithmID
            @eval begin
                """
                    $($h)(data, len[; provider, kwargs...])

                Return the first `len` bytes of the digest of `data` computed with the $($H)
                algorithm.
                """
                $h(data, len; provider = $provider, kwargs...) =
                    digest($algoid, data, len; provider, kwargs...)

                push!(functions.xof, $h)
            end

            provider = select_provider(algoid, streaming_providers)

            if !isnothing(provider)
                @eval begin
                    """
                        $($h)(data[; provider, kwargs...])

                    Return a hash context initialized with `data` for the $($H) algorithm.
                    """
                    $h(data; provider = $provider, kwargs...) =
                        context($algoid, data; provider, kwargs...)
                end
            end
        end
    end
end

end # module
