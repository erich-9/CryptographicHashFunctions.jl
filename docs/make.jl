using Documenter, Hashing

makedocs(
    sitename = "Hashing.jl",
    pages = [
        "Home" => "index.md",
        "installation.md",
        "usage.md",
        "Interface" => ["providers.md", "algorithms.md", "api_high.md", "api_low.md"],
    ],
)

deploydocs(repo = "github.com/erich-9/Hashing.jl.git")
