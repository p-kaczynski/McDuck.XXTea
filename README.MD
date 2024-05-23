# McDuck.XXTea
## An implementation of XXTea algorithm in .NET



### Performance
Please be aware, that this implementation does not take advantage of any special
optimizations in contrast with e.g. AES which is often hardware accelerated.

Below is a sample benchmark, which you can run yourself (McDuck.XXTea.Benchmarks).
It shows that this is way slower than standard Aes, so be aware of that.

The goal of this is to provide simple and easy to use and not very secure encryption
for things that are in no way critical.

_Note: 'N' is byte length of the dataset being encrypted and decrypted, with the last ones being 1MiB and 1GiB_

``` ini

BenchmarkDotNet v0.13.12, Windows 11 (10.0.22631.3593/23H2/2023Update/SunValley3)
Intel Core i7-10875H CPU 2.30GHz, 1 CPU, 16 logical and 8 physical cores
.NET SDK 8.0.105
  [Host]     : .NET 8.0.5 (8.0.524.21615), X64 RyuJIT AVX2
  DefaultJob : .NET 8.0.5 (8.0.524.21615), X64 RyuJIT AVX2

```

| Method | N          | Mean               | Error            | StdDev           | Ratio | RatioSD |
|------- |----------- |-------------------:|-----------------:|-----------------:|------:|--------:|
| **XXTea**  | **255**        |         **1,672.7 ns** |         **17.53 ns** |         **16.39 ns** |  **1.80** |    **0.04** |
| Aes    | 255        |           927.5 ns |         14.08 ns |         12.48 ns |  1.00 |    0.00 |
|        |            |                    |                  |                  |       |         |
| **XXTea**  | **1024**       |         **6,465.4 ns** |         **58.96 ns** |         **52.27 ns** |  **3.23** |    **0.06** |
| Aes    | 1024       |         2,004.6 ns |         35.72 ns |         33.42 ns |  1.00 |    0.00 |
|        |            |                    |                  |                  |       |         |
| **XXTea**  | **1048576**    |     **6,634,299.6 ns** |     **44,362.48 ns** |     **34,635.31 ns** |  **2.90** |    **0.08** |
| Aes    | 1048576    |     2,302,607.7 ns |     43,607.22 ns |     53,553.59 ns |  1.00 |    0.00 |
|        |            |                    |                  |                  |       |         |
| **XXTea**  | **1073741824** | **7,546,097,026.7 ns** | **19,758,738.41 ns** | **18,482,336.17 ns** |  **3.76** |    **0.04** |
| Aes    | 1073741824 | 2,006,420,128.6 ns | 27,882,624.35 ns | 24,717,220.23 ns |  1.00 |    0.00 |
