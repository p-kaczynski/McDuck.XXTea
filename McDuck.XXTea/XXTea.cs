using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace McDuck.XXTea
{
    public static class XXTea
    {
        /// <summary>
        /// XXTea uses 128-bit key, which is by reference four 32-bit uint, but bytes are easier to work with.
        /// Therefore, we just know that we need 128 bits in an array of 8-bit bytes.
        /// </summary>
        private const int KeyLength = 128 / 8;

        private const int BaseRounds = 6;

        private const uint Delta = 0x9e3779b9;

        public static byte[] Encrypt(byte[] plainText, byte[] key)
        {
            PadByteArray(ref plainText);
            return Encrypt(GetSpan(plainText), key).ToArray();
        }

        public static byte[] Decrypt(byte[] cipherText, byte[] key) =>
            RemoveByteArrayPadding(
                    Decrypt(GetSpan(cipherText), key)
                )
                .ToArray();

        private static Span<byte> Encrypt(Span<uint> v, byte[] password)
        {
            var n = v.Length;
            if (n == 0)
                return MemoryMarshal.Cast<uint, byte>(v);

            var rounds = BaseRounds + 52 / n;

            uint sum = 0;

            var key = PrepareKey(password);

            var z = v[n - 1];
            do
            {
                unchecked
                {
                    uint y, p;

                    sum += Delta;
                    var e = (sum >> 2) & 3;
                    for (p = 0; p < n - 1; ++p)
                    {
                        y = v[(int) p + 1];
                        z = v[(int) p] += Mx(y, z, sum, key, p, e);
                    }

                    y = v[0];
                    z = v[n - 1] += Mx(y, z, sum, key, p, e);
                }
            } while (--rounds > 0);

            return MemoryMarshal.Cast<uint, byte>(v);
        }

        private static Span<byte> Decrypt(Span<uint> v, byte[] password)
        {
            var n = (uint) v.Length;
            if (n == 0)
                return MemoryMarshal.Cast<uint, byte>(v);

            var key = PrepareKey(password);

            unchecked
            {
                var rounds = BaseRounds + 52 / n;
                var sum = rounds * Delta;

                var y = v[0];
                do
                {
                    uint z, p;
                    var e = (sum >> 2) & 3;
                    for (p = n - 1; p > 0; --p)
                    {
                        z = v[(int) (p - 1)];
                        y = v[(int) p] -= Mx(y, z, sum, key, p, e);
                    }

                    z = v[(int) (n - 1)];
                    y = v[0] -= Mx(y, z, sum, key, p, e);
                    sum -= Delta;
                } while (--rounds > 0);
            }

            return MemoryMarshal.Cast<uint, byte>(v);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static uint Mx(uint y, uint z, uint sum, Span<uint> key, uint p, uint e)
            => unchecked((((z >> 5) ^ (y << 2)) + ((y >> 3) ^ (z << 4))) ^
                         ((sum ^ y) + (key[(int) ((p & 3) ^ e)] ^ z)));

        private static Span<uint> PrepareKey(byte[] key)
        {
            key = TrimKey(key);
            return MemoryMarshal.Cast<byte, uint>(new(key));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static byte[] TrimKey(byte[] key)
        {
            if (key.Length == 128)
                return key;

            // We will need a transformed one.
            var newKey = new byte[KeyLength];

            switch (key.Length)
            {
                // No key? Suit yourself. We will default to just zeros.
                case 0:
                    return newKey;
                // If the key is too short, we will repeat it until it is of required length
                case < KeyLength:
                {
                    for (var i = 0; i < KeyLength; ++i)
                        newKey[i] = key[i % key.Length];
                    break;
                }
                // If the key is too long, we will cycle around and XOR until we run out
                case > KeyLength:
                {
                    for (var i = 0; i < key.Length; ++i)
                        newKey[i % KeyLength] = (byte) (newKey[i % KeyLength] ^ key[i]);
                    break;
                }
            }

            return newKey;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Span<uint> GetSpan(byte[] data) => MemoryMarshal.Cast<byte, uint>(new(data));

        private static void PadByteArray(ref byte[] data)
        {
            // data: [0][1]..[n]
            // There are sizeof(uint) bytes in uint
            // We need to pad the data, which is easy
            // However we also need to persist the information
            // of how much we padded, so it can be trimmed during decryption,
            // so we will first pad with 0-(sizeof(uint)-1) bytes, and then put the uint
            // representing the padding length at the end.
            // So in total we add sizeof(uint) + data.Length % sizeof(uint) bytes

            // Resize, just pads with 0's
            var remainder = (sizeof(uint) - data.Length % sizeof(uint)) % sizeof(uint);
            Array.Resize(ref data, data.Length + remainder + sizeof(uint));

            // Set last sizeof(uint) bytes to the value of the number of padded bytes
            Array.Copy(BitConverter.GetBytes((uint) remainder), 0, data, data.Length - sizeof(uint), sizeof(uint));
        }

        private static Span<byte> RemoveByteArrayPadding(Span<byte> data)
        {
            // The data is [0][1]...[n], then 0-(sizeof(uint)-1) '0', and then sizeof(uint) bytes describing how many zeroes were added
            var remainder = (int) MemoryMarshal.Read<uint>(data[^sizeof(uint)..]);

            // Slice back to the original data size
            return data[..(data.Length - remainder - sizeof(uint))];
        }
    }
}