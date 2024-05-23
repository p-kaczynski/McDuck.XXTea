using System;
using BenchmarkDotNet.Running;

namespace McDuck.XXTea.Benchmarks;

internal class Program
{
    private static void Main(string[] args)
    {
        var summary = BenchmarkRunner.Run<XXTeaBenchmarks>();

        Console.ReadKey();
    }
}