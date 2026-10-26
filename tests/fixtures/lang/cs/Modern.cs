global using System;
namespace Demo.Modern;

public record Person(string Name, int Age);
public record struct Coord(int X, int Y);
public interface IRepo { string Find(int id); }

public class Service(IRepo repo, string name)
{
    public required string Label { get; init; }
    public string Load(int id) => repo.Find(id);
    public string Raw() => """
        raw "text"
        """;
    public int[] Items() { int[] a = [1, 2, 3]; return a; }
}

public class Program
{
    public static void Main()
    {
        var s = new Service(null, "x") { Label = "l" };
        s.Load(1);
        var p = new Person("a", 1) with { Age = 2 };
        Helper(p);
    }
    private static void Helper(Person p) { }
}
