using Documenter, CryptographicHashFunctions

makedocs(
    sitename = "CryptographicHashFunctions.jl",
    pages = [
        "Home" => "index.md",
        "installation.md",
        "usage.md",
        "Interface" => ["providers.md", "algorithms.md", "api_high.md", "api_low.md"],
    ],
)

deploydocs(repo = "github.com/erich-9/CryptographicHashFunctions.jl.git")
