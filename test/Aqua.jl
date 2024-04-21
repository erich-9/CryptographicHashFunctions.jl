import Aqua
import CryptographicHashFunctions

@testset "Aqua.jl" begin
    Aqua.test_all(CryptographicHashFunctions)
end
