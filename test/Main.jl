import CryptographicHashFunctions:
    CryptographicHashFunctions,
    HashAlgorithmID,
    XOFAlgorithmID,
    providers,
    shake128,
    shake256,
    digest,
    hmac_digest,
    context,
    reset!,
    update!,
    digest!

import Base.Iterators: drop, flatten
import Nettle

extract(xof, pos, len) = (digest!(xof, pos - 1); digest!(xof, len))

testdata1 = ((), UInt8[], b"", "", SubString(""), IOBuffer(""))
testdata2 = ((zeros(UInt8, n) for n ∈ 0:753)..., "alea iacta est", "Ваше здоровье!", "😊")
testdata3 = flatten((testdata1, testdata2))

@testset "known answers: shake" begin
    for data ∈ testdata1
        @test shake128(data, 15) == hex2bytes("7f9c2ba4e88f827d61604550760585")
        @test shake256(data, 15) == hex2bytes("46b9dd2b0ba88d13233b3feb743eeb")

        @test extract(shake128(data), 10_000, 10) == hex2bytes("d685d34876d1b9407723")
        @test extract(shake256(data), 10_000, 10) == hex2bytes("fb9f61d36cc42fbc919e")

        for h ∈ (shake128, shake256)
            xof = h(data)
            @test h(data, 4711) ==
                  [digest!(xof, 42); digest!(xof, 0x815); digest!(xof, 4711 - 42 - 0x815)]
        end
    end
end

for provider ∈ providers
    @testset "$provider" begin
        for algoid ∈ keys(provider.algorithms)
            @testset "$algoid" begin
                args = ifelse(algoid isa XOFAlgorithmID, (123,), ())

                ctx₁ = context(algoid; provider)
                update!(ctx₁, "a")
                ctx₂ = copy(ctx₁)
                update!(ctx₁, "b")
                update!(ctx₂, "b")
                ctx₃ = context(algoid, "a"; provider)
                update!(ctx₃, "b")
                ctx₄ = context(algoid, "ab"; provider)
                ctx₅ = copy(ctx₃)
                update!(ctx₅, "c")
                reset!(ctx₅)
                update!(ctx₅, IOBuffer("ab"))

                dgst = digest(algoid, "ab", args...; provider)

                for ctx ∈ (ctx₁, ctx₂, ctx₃, ctx₄, ctx₅)
                    @test dgst == digest!(ctx, args...)
                end

                reset!(ctx₁)

                @test dgst != digest!(ctx₁, args...)
            end
        end
    end
end

for (i, p₁) ∈ enumerate(providers), p₂ ∈ drop(providers, i)
    @testset "$p₁ vs. $p₂" begin
        for algoid ∈ keys(p₁.algorithms)
            haskey(p₂.algorithms, algoid) || continue

            @testset "$algoid" begin
                args = ifelse(algoid isa XOFAlgorithmID, (123,), ())

                for data ∈ testdata3
                    @test digest(algoid, data, args...; provider = p₁) ==
                          digest(algoid, data, args...; provider = p₂)

                    if algoid isa HashAlgorithmID
                        for key ∈ testdata3
                            @test hmac_digest(algoid, key, data; provider = p₁) ==
                                  hmac_digest(algoid, key, data; provider = p₂)
                        end
                    end
                end
            end
        end
    end
end

@testset "comparison with Nettle.jl" begin
    for h ∈ [
        :md4,
        :md5,
        :ripemd160,
        :sha1,
        :sha224,
        :sha256,
        :sha384,
        :sha512,
        :sha3_224,
        :sha3_256,
        :sha3_384,
        :sha3_512,
        :sm3,
    ]
        hmac_h = Symbol(:hmac_, h)

        @testset "$h" begin
            for data ∈ testdata2
                dgst₁ = getfield(CryptographicHashFunctions, h)(data)
                dgst₂ = Nettle.digest(String(h), data)
                @test dgst₁ == dgst₂

                for key ∈ testdata2
                    dgst₁ = getfield(CryptographicHashFunctions, hmac_h)(key, data)
                    dgst₂ = Nettle.digest(String(h), key, data)
                    @test dgst₁ == dgst₂
                end
            end
        end
    end
end
