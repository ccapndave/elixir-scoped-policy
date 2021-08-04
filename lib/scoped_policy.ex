defmodule ScopedPolicy do
  @moduledoc """
  Provides a way to scope [Bodyguard](https://hexdocs.pm/bodyguard/readme.html) policy `authorize`
  functions.

  [Bodyguard](https://hexdocs.pm/bodyguard/readme.html) is a simple library that provides conventions
  for defining an [authorize](https://hexdocs.pm/bodyguard/Bodyguard.Policy.html#c:authorize/3)
  function that protects boundaries of your application.  The function takes three arguments,
  `action`, `object` and `params`.  The `action` is an atom describing what we are authorizing,
  the `object` is usually the logged in user and the `params` is some value that gives any extra
  information about the action we are performing.

  Although the `object` is most often the logged in user, for more complicated application it may
  contain more information.  For example, If we imagine an Phoenix application that runs on
  multiple subdomains, the authorization might depend on the current subdomain.  In that case
  the `object` could contain both the subdomain and the user:

      %{
        subdomain: :portal,
        current_user: some_user
      }

  or

      %{
        subdomain: :app,
        current_user: some_user
      }

  In this case we may want to have different `authorization` functions depending on the `subdomain`.

      defmodule MyPolicy do

        # Rules for `portal`
        def authorize(:enter, %{subdomain: :portal, current_user: %{role: role}}, _params)
          when role in [:portal_user],
          do: true

        # Rules for `app`
        def authorize(:enter, %{subdomain: :app, current_user: %{role: role}}, _params)
          when role in [:app_user],
          do: true

      end

  Although this works fine, this can become noisy when there are a lot of authorization clauses and
  policy modules.

  This module provides a way to scope authorization functions based on their `object`, as well as
  to transform (_focus_) the `object` for functions within the scope.

  For example, the rules above can be written as:

     defmodule MyPolicy do
        use ScopedPolicy

        def focus_object(%{current_user: current_user}), do: current_user

        scoped_policy match: %{subdomain: :portal}, focus_object: &MyPolicy.focus_object/1 do
          def authorize(:enter, %{role: role}, _params) when role in [:portal_user], do: true
        end

        # Rules for `app`
        scoped_policy match: %{subdomain: :app}, focus_object: &MyPolicy.focus_object/1 do
          def authorize(:enter, %{role: role}, _params) when role in [:app_user], do: true
        end

      end
  """

  @doc """
  Define a scoped policy.

  ## Options

    * `:match` - the pattern to match against the authorization `object`.  This can either be
    a single pattern or a list of patterns, any of which can match.

    * `:parent_policy` - the `authorize` function is called on this policy module before running
    this scope.  This can be used to build hierarchical policies, or to have a global policy.

    * `:focus_object` - a captured function that is applied to the `object` before the `authorize`
    functions are called in this scope.  This is used to _focus_ the object into the relevant shape
    within the scope.

    * `:allow_all?` - this ignores any functions within the scope.  The authorization will always suceed.

    * `:debug` - if this is true, output debug information using the Elixir [Logger](https://hexdocs.pm/logger/1.12/Logger.html)
  """
  defmacro scoped_policy(opts, block) do
    module_name = :"ScopedPolicy#{:erlang.phash2(opts)}"

    quote do
      defmodule unquote(module_name) do
        unquote(block)
        @behaviour Bodyguard.Policy
      end

      @policies {unquote(module_name), unquote(opts)}
    end
  end

  defmacro __using__(_opts) do
    quote do
      Module.register_attribute(__MODULE__, :policies, accumulate: true)

      @before_compile ScopedPolicy

      import ScopedPolicy
    end
  end

  defmacro __before_compile__(_env) do
    quote do
      require Logger
      @behaviour Bodyguard.Policy

      if length(@policies) > 0 do
        def authorize(action, object, params) do
          matching_policy =
            Enum.find(@policies, fn {module_name, opts} ->
              case Keyword.get(opts, :matches) do
                nil -> List.first(@policies)
                values when is_list(values) -> values |> Enum.any?(&match?(^&1, object))
                value -> match?(^value, object)
              end
            end)

          case matching_policy do
            nil ->
              false

            {module_name, opts} ->
              if get_option(opts, :debug),
                do:
                  Logger.debug(
                    "authorize called with [action: #{inspect(action)}, object: #{inspect(object)}, params: #{inspect(params)}]"
                  )

              cond do
                get_option(opts, :allow_all?) == true ->
                  true

                true ->
                  focus_object = get_option(opts, :focus_object, & &1)

                  parent_policy_authorization =
                    case get_option(opts, :parent_policy) do
                      nil ->
                        true

                      parent_policy_module ->
                        apply(parent_policy_module, :authorize, [action, object, params])
                    end

                  parent_policy_authorization &&
                    apply(module_name, :authorize, [action, focus_object.(object), params])
              end
          end
        end
      end
    end
  end

  @doc false
  def get_option(opts, key, default \\ nil),
    do: Keyword.get_lazy(opts, key, fn -> Application.get_env(:scoped_policy, key, default) end)
end
