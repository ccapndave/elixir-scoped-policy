defmodule ScopedPolicy.MixProject do
  use Mix.Project

  def project do
    [
      app: :scoped_policy,
      version: "0.1.0",
      elixir: "~> 1.12",
      start_permanent: Mix.env() == :prod,
      deps: deps(),

      # Docs
      name: "ScopedPolicy",
      source_url: "https://github.com/ccapndave/elixir-scoped-policy",
      docs: [
        main: "ScopedPolicy"
      ]
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:bodyguard, "~> 2.4.1"},
      {:mix_test_watch, "~> 1.0.3", only: :dev, runtime: false},
      {:ex_doc, "~> 0.24", only: :dev, runtime: false}
    ]
  end
end
