defmodule PolicyTest do
  use ExUnit.Case
  doctest ScopedPolicy

  defmodule TestPolicy do
    use ScopedPolicy, log_level: :info

    scoped_policy matches: :a do
      def authorize(:works_with_a, _object, _params), do: true
      def authorize(_action, _object, _params), do: false
    end

    scoped_policy matches: :b do
      def authorize(:works_with_b, _object, _params), do: true
      def authorize(_action, _object, _params), do: false
    end
  end

  defmodule TestOptsPolicy do
    use ScopedPolicy

    scoped_policy allow_all?: true do
      def authorize(_action, _object, _params), do: false
    end
  end

  defmodule TestFocusObjectPolicy do
    use ScopedPolicy

    def focus_object(%{current_user: current_user}), do: current_user

    scoped_policy focus_object: &TestFocusObjectPolicy.focus_object/1 do
      def authorize(:check_dave, :dave, _params), do: true
      def authorize(_action, _object, _params), do: false
    end
  end

  defmodule TestParentPolicy do
    defmodule ParentPolicy do
      use ScopedPolicy

      def authorize(:check, %{app_mode: :one}, _params), do: true
      def authorize(_action, _object, _params), do: false
    end

    use ScopedPolicy, debug: true

    def focus_object(%{current_user: current_user}), do: current_user

    scoped_policy parent_policy: ParentPolicy,
                  focus_object: &TestFocusObjectPolicy.focus_object/1 do
      def authorize(:check, :dave, _params), do: true
      def authorize(_action, _object, _params), do: false
    end
  end

  defmodule TestMapMatches do
    use ScopedPolicy

    scoped_policy matches: %{a: 1} do
      def authorize(:one, _object, _params), do: true
      def authroize(_action, _object, _params), do: false
    end
  end

  test "policy macro" do
    assert :ok = Bodyguard.permit(TestPolicy, :works_with_a, :a)
    assert {:error, :unauthorized} = Bodyguard.permit(TestPolicy, :works_with_b, :a)
    assert :ok = Bodyguard.permit(TestPolicy, :works_with_b, :b)
    assert {:error, :unauthorized} = Bodyguard.permit(TestPolicy, :works_with_a, :b)
  end

  test "allow_all option" do
    assert :ok = Bodyguard.permit(TestOptsPolicy, :anything, :a)
  end

  test "focus object" do
    assert :ok =
             Bodyguard.permit(TestFocusObjectPolicy, :check_dave, %{
               app_mode: :one,
               current_user: :dave
             })
  end

  test "parent policy" do
    assert :ok =
             Bodyguard.permit(TestParentPolicy, :check, %{
               app_mode: :one,
               current_user: :dave
             })
  end

  test "matches" do
    assert :ok = Bodyguard.permit(TestMapMatches, :one, %{a: 1, b: 2, c: 3})
  end
end
