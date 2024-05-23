using System;
using System.Collections.Generic;
using System.Text;
using FluentAssertions;
using Xunit;

namespace McDuck.XXTea.Tests;

public class XXTeaTests
{
    [Fact]
    public void String_Should_Be_Unchanged_By_Encryption_Decryption_Round()
    {
        const string testString = "I would like to slip into something more comfortable - like a coma.";
        const string password = "this is some kind of password";

        var inputBytes = Encoding.UTF8.GetBytes(testString);
        var passBytes = Encoding.UTF8.GetBytes(password);

        var outputBytes = XXTea.Encrypt(inputBytes, passBytes);

        outputBytes.Should().NotEqual(inputBytes, "the ciphertext should not be equal to plaintext");

        outputBytes = XXTea.Decrypt(outputBytes, passBytes);

        var restoredString = Encoding.UTF8.GetString(outputBytes);
        testString.Should().Be(restoredString,
            "the encryption and decryption process should not change the message");
    }

    [Theory]
    [InlineData(43254236)]
    [MemberData(nameof(SeedProvider))]
    public void Random_Data_Encryption_Decryption(int seed)
    {
        var r = new Random(seed);

        var passBytes = new byte[r.Next(8, 2048)];
        r.NextBytes(passBytes);

        var inputBytes = new byte[4096];
        r.NextBytes(inputBytes);

        var outputBytes = XXTea.Encrypt(inputBytes, passBytes);

        outputBytes.Should().NotBeEquivalentTo(inputBytes, "the ciphertext should not be equal to plaintext");

        outputBytes = XXTea.Decrypt(outputBytes, passBytes);

        outputBytes.Should().BeEquivalentTo(inputBytes,
            "the encryption and decryption process should not change the message");
    }

    public static IEnumerable<object[]> SeedProvider()
    {
        yield return new object[] {(int) DateTime.UtcNow.Ticks};
    }
}