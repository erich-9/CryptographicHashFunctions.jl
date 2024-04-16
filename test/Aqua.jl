import Aqua
import Hashing

@testset "Aqua.jl" begin
    Aqua.test_all(Hashing)
end
