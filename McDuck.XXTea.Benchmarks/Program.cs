using System;
using BenchmarkDotNet.Running;

namespace McDuck.XXTea.Benchmarks
{
    class Program
    {
        static void Main(string[] args)
        {
            var summary = BenchmarkRunner.Run<XXTeaBenchmarks>();

            Console.ReadKey();
        }
    }
}
