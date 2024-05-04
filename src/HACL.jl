module HACL

import ..CryptographicHashFunctions as P

lib = "/tmp/libhacl.so"

const supports_streaming = false

const algoid_mapping = Dict(
    P.BLAKE2B_512 => 7,
    P.BLAKE2S_256 => 6,
    P.MD5 => 5,
    P.SHA1 => 4,
    P.SHA224 => 0,
    P.SHA256 => 1,
    P.SHA384 => 2,
    P.SHA512 => 3,
    # P.SHA3_224 => 9,
    P.SHA3_256 => 8,
    # P.SHA3_384 => 10,
    # P.SHA3_512 => 11,
)

const CSpec_Hash_Definitions_hash_alg = UInt8
const CEverCrypt_Error_error_code = Cuchar
const CEverCrypt_Hash_Incremental_state_t = Ptr{Cvoid}

function available(algoid_external)
    true
end

mutable struct Algorithm{T}
    identifier::T
    blocksize::Int
    digestsize::Int
    algoid_external::CSpec_Hash_Definitions_hash_alg

    function Algorithm(algoid::T, algoid_external) where {T}
        blocksize = @ccall lib.Hacl_Hash_Definitions_block_len(
            algoid_external::CSpec_Hash_Definitions_hash_alg,
        )::Cuint
        digestsize = @ccall lib.Hacl_Hash_Definitions_hash_len(
            algoid_external::CSpec_Hash_Definitions_hash_alg,
        )::Cuint

        new{T}(algoid, blocksize, digestsize, algoid_external)
    end
end

mutable struct Context{T} <: P.Context{T}
    algo::Algorithm{T}
    state::CEverCrypt_Hash_Incremental_state_t

    function Context(algoid::T) where {T}
        algo = algorithms[algoid]
        state = @ccall lib.EverCrypt_Hash_Incremental_create_in(
            algo.algoid_external::CSpec_Hash_Definitions_hash_alg,
        )::CEverCrypt_Hash_Incremental_state_t

        res = new{T}(algo, state)
        P.reset!(res)

        finalizer(res) do x
            @ccall lib.EverCrypt_Hash_Incremental_free(
                x.state::CEverCrypt_Hash_Incremental_state_t,
            )::Cvoid
        end
    end
end

Base.copy(ctx::Context) = @error "HACL: copying contexts not implemented"

function P.reset!(ctx::Context)
    @ccall lib.EverCrypt_Hash_Incremental_init(
        ctx.state::CEverCrypt_Hash_Incremental_state_t,
    )::Cvoid
end

function P.update!(ctx::Context, data::AbstractVector{UInt8}, len::Integer = length(data))
    rc = @ccall lib.EverCrypt_Hash_Incremental_update(
        ctx.state::CEverCrypt_Hash_Incremental_state_t,
        data::Ptr{Cuchar},
        len::Csize_t,
    )::CEverCrypt_Error_error_code
    rc == 0 || error("EverCrypt_Hash_Incremental_update failed")

    nothing
end

function P.digest!(ctx::Context)
    res = Vector{UInt8}(undef, ctx.algo.digestsize)

    @ccall lib.EverCrypt_Hash_Incremental_finish(
        ctx.state::CEverCrypt_Hash_Incremental_state_t,
        res::Ptr{Cuchar},
    )::Cvoid

    res
end

begin
    for (algoid, algoid_external) ∈ copy(algoid_mapping)
        if !available(algoid_external)
            delete!(algoid_mapping, algoid)
            @info "HACL: $algoid not provided"
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
