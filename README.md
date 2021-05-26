<p align="center">
<a href="https://dotnet.microsoft.com/download/dotnet/5.0" rel="nofollow"><img src="https://img.shields.io/badge/core-v3.1%20or%20higher-lightgrey?style=for-the-badge&logo=dot-net&logoColor=white" title=".NET Core v3.1 LTS or higher" alt=".NET Core"></a>
<a href="https://github.com/Roydl/Crypto/actions"><img src="https://img.shields.io/badge/cross%E2%80%93platform-%e2%9c%94-blue?style=for-the-badge&logo=linux&logoColor=silver" title="Automatically tested with Windows 10 &amp; Ubuntu 20.04 LTS" alt="Cross-platform"></a>
<a href="https://github.com/Roydl/Crypto/blob/master/LICENSE.txt"><img src="https://img.shields.io/github/license/Roydl/Crypto?style=for-the-badge" title="Read the license terms" alt="License"></a>
</p>
<p align="center">
<a href="https://github.com/Roydl/Crypto/actions/workflows/dotnet.yml"><img src="https://img.shields.io/github/workflow/status/Roydl/Crypto/build%2Btest?style=for-the-badge&label=build%2Btest&logo=github&logoColor=silver" title="Check the last workflow results" alt="Build+Test"></a>
<a href="https://github.com/Roydl/Crypto/commits/master"><img src="https://img.shields.io/github/last-commit/Roydl/Crypto?style=for-the-badge&logo=github&logoColor=silver" title="Check the last commits" alt="Commits"></a>
<a href="https://github.com/Roydl/Crypto/archive/refs/heads/master.zip"><img src="https://img.shields.io/badge/download-source-important?style=for-the-badge&logo=github&logoColor=silver" title="Start downloading the &apos;master.zip&apos; file" alt="Source"></a>
</p>
<p align="center">
<a href="https://www.nuget.org/packages/Roydl.Crypto"><img src="https://img.shields.io/nuget/v/Roydl.Crypto?style=for-the-badge&logo=nuget&logoColor=silver&label=nuget" title="Check out the NuGet package page" alt="NuGet"></a>
<a href="https://www.nuget.org/packages/Roydl.Crypto"><img src="https://img.shields.io/nuget/dt/Roydl.Crypto?logo=nuget&logoColor=silver&style=for-the-badge" title="Check out the NuGet package page" alt="NuGet"></a>
<a href="https://www.si13n7.com"><img src="https://img.shields.io/website/https/www.si13n7.com?style=for-the-badge&down_color=critical&down_message=down&up_color=success&up_message=up&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAEwSURBVDhPxZJNSgNBEIXnCp5AcCO4CmaTRRaKBhdCFkGCCKLgz2Y2RiQgCiqZzmi3CG4COj0X8ApewSt4Ba%2FQ9leZGpyVG8GComtq3qv3qmeS%2Fw9nikHMd5sVn3bqLx7zom1NcW8z%2F6G9CjoPm722rPEv45EJ21vD0O30AvX12IWDvTRsrPXrnjPlUYO0u3McVpZXhch5cnguZ7vVDWfpjRAZgPqc%2BIMEgKQe9Pfr0xn%2FBqZJjAUNQKilp5cC1gHYYz8Usc3OQsTz9HZWK5BMJwFDwrbWbuIXhfhg%2FDpWuE2mK5lEgQtiz4baU14u3V09i5peiipy6qVAxFWtZiflJiq8AAiIZx1CnxpStGmEpEHDZf4r2pUd%2BMjYxomoxJofo4L%2FHqyR57OF6vEvIkm%2BAYRc%2BWd4P97CAAAAAElFTkSuQmCC" title="Visit the developer&apos;s website" alt="Website"></a>
<a href="https://www.si13n7.de"><img src="https://img.shields.io/website/https/www.si13n7.de?style=for-the-badge&down_color=critical&down_message=down&label=mirror&up_color=success&up_message=up&logo=data%3Aimage%2Fpng%3Bbase64%2CiVBORw0KGgoAAAANSUhEUgAAAA4AAAAOCAYAAAAfSC3RAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAEwSURBVDhPxZJNSgNBEIXnCp5AcCO4CmaTRRaKBhdCFkGCCKLgz2Y2RiQgCiqZzmi3CG4COj0X8ApewSt4Ba%2FQ9leZGpyVG8GComtq3qv3qmeS%2Fw9nikHMd5sVn3bqLx7zom1NcW8z%2F6G9CjoPm722rPEv45EJ21vD0O30AvX12IWDvTRsrPXrnjPlUYO0u3McVpZXhch5cnguZ7vVDWfpjRAZgPqc%2BIMEgKQe9Pfr0xn%2FBqZJjAUNQKilp5cC1gHYYz8Usc3OQsTz9HZWK5BMJwFDwrbWbuIXhfhg%2FDpWuE2mK5lEgQtiz4baU14u3V09i5peiipy6qVAxFWtZiflJiq8AAiIZx1CnxpStGmEpEHDZf4r2pUd%2BMjYxomoxJofo4L%2FHqyR57OF6vEvIkm%2BAYRc%2BWd4P97CAAAAAElFTkSuQmCC" title="Visit the developer&apos;s mirror website" alt="Mirror"></a>
</p>


# Roydl.Crypto

The idea was to create a handy way to hash and encrypt data.

You can easily create instances of any type to translate `Stream`, `byte[]` or `string` data. With the exception of `Rijndael` encryption and decryption, extension methods are also provided for all types.


### Checksum Encryption:

| Name | Hash Size | Algorithm | HMAC |
| ---- | ---- | ---- | ---- |
| Adler32 | 32 | Standard | unsupported |
| CRC16 | 16 | AUG-CCITT | unsupported |
| CRC32 | 32 | Standard | unsupported |
| CRC64 | 64 | ECMA | unsupported |
| MD5 | 128 | Standard | optional |
| SHA1 | 160 | Standard | optional |
| SHA256 | 256 | SHA-2 Standard | optional |
| SHA384 | 384 | SHA-2 Standard | optional |
| SHA512 | 512 | SHA-2 Standard | optional |

_I hope I don't have to say that checksums shouldn't be used to verify sensitive data!_

#### Usage:
```cs
// The `value` can be almost anything.
string strHash = value.GetChecksum(ChecksumAlgo.Sha512);

// The file encryption has an additional method, where `value` must be a
// `string` with a valid file path.
string strHash = value.GetFileChecksum(); // SHA-256 is used by default.

// The `GetCipher` extension method retrieves an unsigned 64-bit integer
// representation of the computed hash. It follows the same rules outlined
// earlier.
ulong numHash = value.GetCipher(ChecksumAlgo.Crc64);

// HMAC is supported via instances by setting the secret key. 
Sha512 instance1 = new Sha512()
{
    SecretKey = new byte[128] { /* some bytes */ }
};

// Encryptions uses the secret key until `DestroySecretKey()` is called.
instance1.Encrypt(value);

// `RawHash` stores the raw data of the last computed hash code.
byte[] bytesHash = instance1.RawHash;

// `HashNumber` holds the 64-bit unsigned integer representation of the
// last computed hash code. In case of CRC, this is the real raw hash code.
ulong numHash = instance1.HashNumber;

// `Hash` returns the string representation of the last computed hash code
// where letters are always in lowercase.
string lowercase = instance1.Hash;

// `Hash` corresponds to`ToString()` in which an additional boolean value
// can be specified for uppercase letters.
string uppercase = instance1.ToString(true);

// The last thing you need to know is that instances have equality operators.
bool equ = (instance1 == instance2);
bool neq = (instance1 != instance2);
```

#### CRC customization:

If you need a different CRC algorithm, you can easily create your own variations. This is an example for `CRC-32/POSIX`, but it should support many others between 8 and 64 bits.

```cs
public sealed class Crc32Posix : ChecksumAlgorithm<Crc32Posix>
{
    private const int Bits = 32;
    private const uint Poly = 0x04c11db7u;
    private const uint Init = 0x00000000u;
    private const bool RefIn = false;
    private const bool RefOut = false;
    private const uint XorOut = 0xffffffffu;

    // Sets a new `CrcConfig` with the constants from above.
    private static readonly CrcConfig<uint> Current = new(Bits, Poly, Init, RefIn, RefOut, XorOut);

    // At least one constructor is required because `base(bits)` has to
    // be called.
    public Crc32Posix() : base(Bits) { }

    // Lets `CrcConfig` struct do the job. This method is the only one
    // that needs to be overwritten.
    public override void Encrypt(Stream stream)
    {
        if (stream == null)
            throw new ArgumentNullException(nameof(stream));
        Current.ComputeHash(stream, out var num);
        HashNumber = num;
        RawHash = CryptoUtils.GetByteArray(num, RawHashSize, true);
    }
}
```

---

### Other included algorithm:

| Name | Algorithm |
| ---- | ---- |
| Rijndael | `128` bit block size; optional: `128`, `192` or `256` bit key size, `cipher` and `padding` modes |


#### Usage:
```cs
byte[] password = new byte[] { /* some bytes */ };
byte[] salt = new byte[] { /* some bytes */ };
using var aes = new Rijndael(password, salt, 1000, SymmetricKeySize.Large);

byte[] encryptedBytes = aes.EncryptBytes(new byte[] { /* some bytes */ });
byte[] encryptedFile = aes.EncryptFile("C:\\FileToEncrypt.example");
aes.EncryptFile("C:\\FileToEncrypt.example", "C:\\EncryptedFile.example");

aes.EncryptStream(streamToEncrypt, encryptedStream);

byte[] decryptedBytes = aes.DecryptBytes(new byte[] { /* some bytes */ });
byte[] decryptedFile = aes.DecryptFile("C:\\Some\\File.source");
aes.DecryptFile("C:\\FileToDecrypt.example", "C:\\DecryptedFile.example");

aes.DecryptStream(streamToDecrypt, decryptedStream);
```

---


## Would you like to help?

- [Star this Project](https://github.com/Roydl/Crypto/stargazers) :star: and show me that this project interests you :hugs:
- [Open an Issue](https://github.com/Roydl/Crypto/issues/new) :coffee: to give me your feedback and tell me your ideas and wishes for the future :sunglasses:
- [Open a Ticket](https://www.si13n7.com/?page=contact) :mailbox: if you don't have a GitHub account, you can contact me directly on my website :wink:
- [Donate by PayPal](https://paypal.me/si13n7/) :money_with_wings: to buy me some cakes :cake:

_Please note that I cannot fix bugs that are unknown to me. So do yourself and me the favor and get in touch with me._ :face_with_head_bandage: