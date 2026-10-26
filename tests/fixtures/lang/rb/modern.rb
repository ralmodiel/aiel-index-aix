# frozen_string_literal: true

Point = Data.define(:x, :y) do
  def dist = Math.sqrt(x * x + y * y)
end

class Repo
  def find(id) = "item #{id}"
end

class Service
  def initialize(repo) = @repo = Repo.new

  def run(id, key: 1, **opts)
    case [id, key]
    in [Integer => a, 1] then helper(a)
    in {name:} then helper(name)
    else nil
    end
    @repo.find(id)
    items.map { it.to_s }
  end

  def forward(...) = helper(...)

  private

  def helper(x) = x
end
