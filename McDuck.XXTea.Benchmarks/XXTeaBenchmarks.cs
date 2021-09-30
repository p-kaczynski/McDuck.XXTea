using System;
using System.IO;
using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace McDuck.XXTea.Benchmarks
{
    public class XXTeaBenchmarks : IDisposable
    {
        
        private byte[] _data;
        private byte[] _key;
        private ICryptoTransform _aesEnc;
        private ICryptoTransform _aesDec;

        [Params(255,1024,1024*1024, 1024*1024*1024)]
        public int N { get; set; }

        [GlobalSetup]
        public void Setup()
        {
            _data = new byte[N];
            var r = new Random(42);
            r.NextBytes(_data);

            var aes = System.Security.Cryptography.Aes.Create();
            aes.GenerateIV();
            aes.GenerateKey();
            aes.Padding = PaddingMode.PKCS7;

            _aesEnc = aes.CreateEncryptor();
            _aesDec = aes.CreateDecryptor();

            _key = new byte[128/8];
            r.NextBytes(_key);
        }

        [Benchmark]
        public byte[] XXTea() => McDuck.XXTea.XXTea.Decrypt(McDuck.XXTea.XXTea.Encrypt(_data, _key), _key);

        [Benchmark(Baseline = true)]
        public byte[] Aes()
        {
            byte[] encrypted;
            using (var ms = new MemoryStream())
            {
                using (var csEncrypt = new CryptoStream(ms, _aesEnc, CryptoStreamMode.Write))
                {

                    csEncrypt.Write(_data, 0, _data.Length);
                    csEncrypt.FlushFinalBlock();
                    encrypted = ms.ToArray();
                }
            }

            byte[] decrypted = new byte[encrypted.Length];
            using (var ms2 = new MemoryStream(encrypted))
            using (var csDecrypt = new CryptoStream(ms2, _aesDec, CryptoStreamMode.Read))
            {

                csDecrypt.Read(decrypted,0,encrypted.Length);
            }

            return decrypted;
        }

        public void Dispose()
        {
            _aesEnc?.Dispose();
            _aesDec?.Dispose();
        }
    }
}